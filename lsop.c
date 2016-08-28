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

static int hflag = 0;

enum ScanResult {
	/* no problems found */
	ScanResult_okay,
	/* scan process failed, check |errno| */
	ScanResult_err,
	/* process references object changed on disk (replaced) */
	ScanResult_mismatch,
	/* process references object no longer on disk (deleted) */
	ScanResult_missing
};

static const int EXIT_OUTDATED = 2;

static enum ScanResult
scan_process(struct procstat *prstat,
	     struct kinfo_proc *proc)
{
	struct kinfo_vmentry *head;
	unsigned i, cnt;
	struct stat st;
	int rv, res = ScanResult_okay;
	static const int prot = KVME_PROT_READ | KVME_PROT_EXEC;

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
				rv = stat(it->kve_path, &st);
				if (rv == -1) {
					res = errno == ENOENT ? ScanResult_missing : ScanResult_err;
					break;
				}
				if (rv == 0 &&
				    (st.st_dev != (dev_t)it->kve_vn_fsid ||
				     st.st_ino != (ino_t)it->kve_vn_fileid)) {
					/* never gets here, as if .so is moved/deleted
					 * |it->kve_path| gets empty */
					res = ScanResult_mismatch;
					break;
				}
			} else {
				res = ScanResult_missing;
				break;
			}
		}
	}
	free(head);
	return res;
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
	fputs(" -h      omit table header\n", stderr);
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

	while ((opt = getopt(argc, argv, "h")) != -1) {
		switch (opt) {
		case 'h': hflag = 1; break;
		default: return usage();
		}
	}

	if (injail() > 0) {
		fputs("lsop does not currently work in a jail\n", stderr);
		return EXIT_FAILURE;
	}

	prstat = procstat_open_sysctl();
	if (prstat == NULL)
		errx(1, "procstat_open()");

	p = procstat_getprocs(prstat, KERN_PROC_PROC, 0, &cnt);
	if (p == NULL)
		errx(1, "procstat_getprocs()");

	for (i = 0; i < cnt; i++) {
		enum ScanResult rv;
		proc = p + i;

		if (procstat_getpathname(prstat, proc, path, sizeof(path)) == 0) {
			if (strlen(path) == 0)
				strcpy(path, "-");
			rv = scan_process(prstat, proc);
		} else {
			snprintf(path, sizeof(path), "(%s)", proc->ki_comm);
			rv = errno == ENOENT ? ScanResult_missing : ScanResult_err;
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
				status = "miss";
				break;
			}

			if (!hflag) {
				fprintf(stdout, "%6s %6s %4s %s\n",
					"pid", "jid", "stat", "command");
				hflag = 1;
			}
			++n;
			fprintf(stdout, "%6u %6u %4s %s\n",
				(unsigned)proc->ki_pid,
				(unsigned)proc->ki_jid,
				status,
				path);
		}
	}
	procstat_freeprocs(prstat, p);
	procstat_close(prstat);

	if (res)
		return EXIT_FAILURE;
	if (n)
		return EXIT_OUTDATED;
	return EXIT_SUCCESS;
}
