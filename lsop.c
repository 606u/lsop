#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <err.h>
#include <getopt.h>
#include <libprocstat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

/* omit table header */
static int hflag = 0;
/* create a whitelist from system state, save to given path */
static const char *cflag = 0;
/* load whitelist to suppress some warnings from given path */
static const char *wflag = 0;

enum ScanResult {
	/* no problems found */
	ScanResult_okay,
	/* scan process failed, check |errno| */
	ScanResult_err,
	/* process references object changed on disk (replaced) */
	/* at this time this case cannot be detected (see below) */
	ScanResult_mismatch,
	/* process references object no longer on disk (deleted) */
	ScanResult_missing
};

static const int EXIT_OUTDATED = 2;

/* a process whitelisted to give false positives */
struct whitelisted_process {
	struct whitelisted_process *next;

	char path[PATH_MAX];

	size_t n_anon_mmap_rx_vn_areas;
};


static void
free_whitelist(struct whitelisted_process *head)
{
	struct whitelisted_process *it = head;
	while (it) {
		struct whitelisted_process *next = it->next;
		free(it);
		it = next;
	}
}


static int
read_whitelist(struct whitelisted_process **head)
{
	FILE *fp;
	char buf[PATH_MAX + 20];
	char *p;
	int res = 0;

	if (strcmp(wflag, "-")) {
		fp = fopen(wflag, "r");
		if (!fp) {
			fprintf(stderr, "lsop: cannot open file '%s': %s\n",
				wflag, strerror(errno));
			return -1;
		}
	} else {
		fp = stdin;
	}

	/* format is "/path/to/process\t<number>" */
	while ((p = fgets(buf, sizeof(buf), fp)) != 0) {
		const char *tab = strchr(buf, '\t');
		char *eol = 0;
		unsigned long n;
		struct whitelisted_process *proc;

		if (tab &&
		    (n = strtoul(tab + 1, &eol, 10)) > 0 &&
		    eol && *eol == '\n') {
			if ((proc = malloc(sizeof(*proc))) != 0) {
				memcpy(proc->path, buf, tab - buf);
				proc->path[tab - buf] = '\0';
				proc->n_anon_mmap_rx_vn_areas = (size_t)n;
				*head = proc;
				head = &proc->next;
			} else {
				fprintf(stderr, "lsop: cannot read '%s': %s\n",
					wflag, strerror(ENOMEM));
				res = -1;
				break;
			}
		} else {
			if (strlen(p)) {
				fprintf(stderr, "lsop: cannot read '%s': bad file format\n", wflag);
				res = -1;
			}
			break;
		}
	}
	if (fp != stdin) {
		fclose(stdin);
	}
	return res;
}


static const struct whitelisted_process*
find_proc(const struct whitelisted_process *head,
	  const char *procpath)
{
	const struct whitelisted_process *it = head;
	while (it) {
		if (!strcmp(it->path, procpath)) {
			return it;
		}
		it = it->next;
	}
	return 0;
}


static enum ScanResult
scan_process(struct procstat *prstat,
	     struct kinfo_proc *proc,
	     size_t *out_n_missing)
{
	struct kinfo_vmentry *head;
	unsigned i, cnt;
	struct stat st;
	static const int prot = KVME_PROT_READ | KVME_PROT_EXEC;
	size_t n_errs = 0, n_missing = 0, n_mismatched = 0;

	head = procstat_getvmmap(prstat, proc, &cnt);
	if (!head)
		return ScanResult_err;

	for (i = 0; i < cnt; ++i) {
		struct kinfo_vmentry *it = head + i;
		/* requirements to consider VM mapping for further test:
		 *  - to have a backing vnode,
		 *  - to be shared (even tho I don't quite understand that :),
		 *  - to be read-only + execute */
		if (it->kve_type == KVME_TYPE_VNODE &&
		    it->kve_shadow_count &&
		    (it->kve_protection & prot) == prot) {
			if (strcmp(it->kve_path, "")) {
				int rv = stat(it->kve_path, &st);
				if (rv == -1) {
					if (errno == ENOENT) {
						++n_missing;
					} else {
						++n_errs;
					}
				} else if (st.st_dev != (dev_t)it->kve_vn_fsid ||
					   st.st_ino != (ino_t)it->kve_vn_fileid) {
					/* never gets here, as if .so is moved/deleted
					 * |it->kve_path| gets empty */
					++n_mismatched;
				}
			} else {
				++n_missing;
			}
		}
	}
	free(head);

	if (out_n_missing) {
		*out_n_missing = n_missing;
	}

	/* ordered from most important to least important state */
	if (n_missing) {
		return ScanResult_missing;
	} else if (n_mismatched) {
		return ScanResult_mismatch;
	} else if (n_errs) {
		return ScanResult_err;
	}
	return ScanResult_okay;
}


static int
injail(void)
{
	int jailed;
	size_t len = sizeof(jailed);
	int rv = sysctlbyname("security.jail.jailed", &jailed, &len, 0, 0);
	return rv == 0 ? jailed : -1;
}


static int
usage(void)
{
	fputs("Lists processes running with outdated binaries or shared libraries\n", stderr);
	fputs("usage: lsop [ options ]\n", stderr);
	fputs("where options are:\n", stderr);
	fputs(" -c path   create whitelist from system state\n", stderr);
	fputs(" -w path   use existing whitelist\n", stderr);
	fputs(" -h        omit table header\n", stderr);
	fputs("\n", stderr);
	fputs("exit codes:\n", stderr);
	fprintf(stderr, " %u  no processes need restarting\n", EXIT_SUCCESS);
	fprintf(stderr, " %u  an error occured\n", EXIT_FAILURE);
	fprintf(stderr, " %u  one or more processes need restarting\n", EXIT_OUTDATED);
	return EX_USAGE;
}


int
main(int argc, char *argv[])
{
	struct procstat *prstat;
	struct kinfo_proc *p, *proc;
	unsigned i, cnt, res = 0, n = 0;
	char path[PATH_MAX];
	int opt;
	struct whitelisted_process *wl_proc = 0;
	FILE *out = stdout, *wl_out = 0;

	while ((opt = getopt(argc, argv, "c:w:h")) != -1) {
		switch (opt) {
		case 'c': cflag = optarg; break;
		case 'w': wflag = optarg; break;
		case 'h': hflag = 1; break;
		default: return usage();
		}
	}

	if (cflag && wflag) {
		fputs("lsop: -c and -w cannot be applied simultaneously\n", stderr);
		return 1;
	}

	if (injail() > 0) {
		fputs("lsop does not currently work in a jail\n", stderr);
		return EXIT_FAILURE;
	}

	if (wflag) {
		if (read_whitelist(&wl_proc) == -1) {
			return 1;
		}
	}

	prstat = procstat_open_sysctl();
	if (prstat == NULL)
		errx(1, "procstat_open()");

	p = procstat_getprocs(prstat, KERN_PROC_PROC, 0, &cnt);
	if (p == NULL)
		errx(1, "procstat_getprocs()");

	if (cflag && !strcmp(cflag, "-")) {
		/* user asked whitelist to be printed in stdout,
		 * therefore messages can no longer go there */
		out = stderr;
		wl_out = stdout;
	}

	for (i = 0; i < cnt; i++) {
		enum ScanResult rv;
		size_t n_missing = 0;
		proc = p + i;

		if (procstat_getpathname(prstat, proc, path, sizeof(path)) == 0) {
			const struct whitelisted_process *whp = 0;
			if (strlen(path)) {
				whp = find_proc(wl_proc, path);
			} else {
				strcpy(path, "-");
			}
			rv = scan_process(prstat, proc, &n_missing);
			if (whp) {
				if (rv == ScanResult_missing) {
					if (n_missing == whp->n_anon_mmap_rx_vn_areas) {
						/* whitelisted */
						rv = ScanResult_okay;
					}
				}
			}
		} else {
			snprintf(path, sizeof(path), "(%s)", proc->ki_comm);
			rv = errno == ENOENT ? ScanResult_missing : ScanResult_err;
			if (rv == ScanResult_missing && cflag) {
				/* process path cannot be retrieved
				 * when binary have been deleted or
				 * upgraded, therefore this is not the
				 * right time to create a whitelist */
				fprintf(stderr, "lsop: whitelist not created: cannot get process %u path\n", proc->ki_pid);
				if (wl_out && wl_out != stdout) {
					fclose(wl_out);
					unlink(cflag);
				}
				return 1;
			}
		}

		if (rv != ScanResult_okay) {
			const char *status = 0;
			switch (rv) {
			case ScanResult_okay:
				break;
			case ScanResult_err:
				status = "err";
				res = 1;
				break;
			case ScanResult_mismatch:
				status = "outd";
				break;
			case ScanResult_missing:
				if (cflag) {
					if (!wl_out) {
						wl_out = fopen(cflag, "w");
						if (!wl_out) {
							fprintf(stderr, "lsop: cannot create whitelist file '%s': %s\n", cflag, strerror(errno));
							return 1;
						}
					}
					fprintf(wl_out, "%s\t%u\n", path, (unsigned)n_missing);
				}
				status = "miss";
				break;
			}

			if (!hflag) {
				fprintf(out, "%6s %6s %4s %s\n",
					"pid", "jid", "stat", "command");
				hflag = 1;
			}
			++n;
			fprintf(out, "%6u %6u %4s %s\n",
				(unsigned)proc->ki_pid,
				(unsigned)proc->ki_jid,
				status,
				path);
		}
	}
	procstat_freeprocs(prstat, p);
	procstat_close(prstat);
	free_whitelist(wl_proc);

	if (wl_out && wl_out != stdout) {
		if (fclose(wl_out)) {
			fprintf(stderr, "lsop: cannot write file '%s': %s\n",
				cflag, strerror(errno));
		}
	}

	if (res) {
		if (cflag)
			fputs("lsop: be aware, that errors were encountered while creating this whitelist\n", stderr);
		return EXIT_FAILURE;
	}
	if (n)
		return EXIT_OUTDATED;
	return EXIT_SUCCESS;
}
