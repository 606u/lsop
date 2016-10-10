#include "lsop.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <err.h>
#include <getopt.h>
#include <libprocstat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

/* omit table header */
int hflag = 0;
/* create a whitelist from system state, save to given path */
const char *cflag = 0;
/* load whitelist to suppress some warnings from given path */
const char *wflag = 0;
/* use a statefile to know which mount point/inode is which file */
const char *sflag = 0;
/* recurse directories when using statefile */
int rflag = 0;
/* follow symlinks when scanning directories */
int fflag = 0;
/* verbosity level */
int vflag = 0;

static const int EXIT_OUTDATED = 2;

int
lsop_scan_mmapped_entry(struct procstat *procstat,
			struct kinfo_proc *proc,
			struct kinfo_vmentry *map,
			/*struct LsopMmappedState*/ void *udata)
{
	struct LsopMmappedState *state = (struct LsopMmappedState*)udata;

	(void)procstat; (void)proc;
	if (strcmp(map->kve_path, "")) {
		struct stat st;
		int rv = stat(map->kve_path, &st);
		if (rv == -1) {
			if (errno == ENOENT) {
				++state->n_missing;
			} else {
				++state->n_errs;
			}
		} else if (st.st_dev != (dev_t)map->kve_vn_fsid ||
			   st.st_ino != (ino_t)map->kve_vn_fileid) {
			/* never gets here, as if .so is moved/deleted
			 * |it->kve_path| gets empty */
			++state->n_mismatched;
		}
	} else {
		++state->n_missing;
	}
	return 0;
}


void
lsop_reset_mmapped_state(struct LsopMmappedState *state)
{
	state->n_errs = state->n_missing = state->n_mismatched = 0;
}


int
lsop_enum_process_mmappings(struct procstat *procstat,
			    struct kinfo_proc *proc,
			    int (*callback)(struct procstat *procstat,
					    struct kinfo_proc *proc,
					    struct kinfo_vmentry *map,
					    void *udata),
			    void *udata)
{
	unsigned cnt;
	struct kinfo_vmentry *head = procstat_getvmmap(procstat, proc, &cnt);
	if (!head)
		return -1;

	int res = 0;
	for (unsigned i = 0; res == 0 && i < cnt; ++i) {
		static const int prot = KVME_PROT_READ | KVME_PROT_EXEC;
		struct kinfo_vmentry *it = head + i;
		/* requirements to consider VM mapping for further test:
		 *  - to have a backing vnode,
		 *  - to be read-only + execute */
		if (it->kve_type == KVME_TYPE_VNODE &&
		    (it->kve_protection & prot) == prot) {
			res = callback(procstat, proc, it, udata);
		}
	}
	free(head);
	return res;
}


int
lsop_enum_processes(int (*callback)(struct procstat *procstat,
				    struct kinfo_proc *proc,
				    const char *exe_path,
				    void *udata),
		    void *udata)
{
	struct procstat *procstat = procstat_open_sysctl();
	if (!procstat) {
		return -EXIT_FAILURE;
	}

	unsigned cnt;
	struct kinfo_proc *proclist =
		procstat_getprocs(procstat, KERN_PROC_PROC, 0, &cnt);
	if (!proclist) {
		return -EXIT_FAILURE;
	}

	int res = 0;
	for (unsigned i = 0; res == 0 && i < cnt; i++) {
		char exe_path[PATH_MAX];
		struct kinfo_proc *proc = proclist + i;
		if (procstat_getpathname(procstat, proc,
					 exe_path, sizeof exe_path) != 0) {
			snprintf(exe_path, sizeof exe_path,
				 "(%s)", proc->ki_comm);
		}

		res = callback (procstat, proc, exe_path, udata);
	}
	procstat_freeprocs(procstat, proclist);
	procstat_close(procstat);

	return res;
}


enum ScanResult
lsop_analyze_result(const struct LsopMmappedState *mmap_res,
		    int lsop_enum_process_mmappings_res)
{
	/* ordered from most important to least important state */
	enum ScanResult res = ScanResult_okay;
	if (mmap_res->n_missing) {
		res = ScanResult_missing;
	} else if (mmap_res->n_mismatched) {
		res = ScanResult_mismatch;
	} else if (mmap_res->n_errs ||
		   lsop_enum_process_mmappings_res != 0) {
		res = ScanResult_err;
	}
	return res;
}


void
lsop_print_process_status(struct procstat *procstat,
			  struct kinfo_proc *proc,
			  const char *exe_path,
			  enum ScanResult res)
{
	static const char *statuses[] = {
		"-", "err", "outd", "miss"
	};

	(void)procstat;
	if (!hflag) {
		fprintf(stdout, "%6s %6s %4s %s\n",
			"pid", "jid", "stat", "command");
		hflag = 1;
	}
	fprintf(stdout, "%6u %6u %4s %s\n",
		(unsigned)proc->ki_pid,
		(unsigned)proc->ki_jid,
		statuses[res],
		exe_path);
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
	puts("usage: lsop [-hv]");
	puts("            [-hv] -c|w whitelist");
	puts("            [-hvrf] -s statefile dir1 [dir2...]");
	return EX_USAGE;
}


int
main(int argc, char *argv[])
{
	int opt;
	while ((opt = getopt(argc, argv, "hvc:w:rfs:")) != -1) {
		switch (opt) {
		case 'h': hflag = 1; break;
		case 'v': ++vflag; break;
		case 'c': cflag = optarg; break;
		case 'w': wflag = optarg; break;
		case 'r': rflag = 1; break;
		case 'f': fflag = 1; break;
		case 's': sflag = optarg; break;
		default: return usage();
		}
	}

	if (cflag && wflag)
		errx(EX_USAGE, "-c and -w cannot be applied simultaneously");
	if (cflag && strlen(cflag) > PATH_MAX - 2)
		errx(EX_USAGE, "whitelist path is too long (-c)");

	if (injail() > 0)
		errx(EX_USAGE, "does not currently work in a jail");

	if ((rflag || fflag) && !sflag)
		errx(EX_USAGE, "-r and -f require -s");

	if (cflag || wflag)
		return lsop_whitelist();
	if (sflag) {
		if (strlen(sflag) > PATH_MAX - 2)
			errx(EX_USAGE, "state file path is too long (-s)");
		return lsop_stateful(argc - optind, argv + optind);
	}
	return lsop_basic();
}
