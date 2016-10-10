#if !defined (LSOP_H)
#  define LSOP_H

/* flags */
extern int hflag;
/* create a whitelist from system state, save to given path */
extern const char *cflag;
/* load whitelist to suppress some warnings from given path */
extern const char *wflag;
/* use a statefile to know which mount point/inode is which file */
extern const char *sflag;
/* recurse directories when using statefile */
extern int rflag;
/* follow symlinks when scanning directories */
extern int fflag;
/* verbosity level */
extern int vflag;

#define trace(lvl, msg, ...)					\
	do {							\
		if (lvl <= vflag) {				\
			warnx("<%d> " msg, lvl, __VA_ARGS__);	\
		}						\
	} while (0)

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

struct procstat;
struct kinfo_proc;
struct kinfo_vmentry;

struct LsopMmappedState {
	unsigned n_errs, n_missing, n_mismatched;
};

int lsop_scan_mmapped_entry(struct procstat *procstat,
			    struct kinfo_proc *proc,
			    struct kinfo_vmentry *map,
			    /*struct LsopMmappedState*/ void *udata);
void lsop_reset_mmapped_state(struct LsopMmappedState *state);

int lsop_enum_process_mmappings(struct procstat *procstat,
				struct kinfo_proc *proc,
				int (*callback)(struct procstat *procstat,
						struct kinfo_proc *proc,
						struct kinfo_vmentry *map,
						void *udata),
				void *udata);

int lsop_enum_processes(int (*callback)(struct procstat *procstat,
					struct kinfo_proc *proc,
					const char *exe_path,
					void *udata),
			void *udata);

enum ScanResult lsop_analyze_result(const struct LsopMmappedState *mmap_res,
				    int lsop_enum_process_mmappings_res);

void lsop_print_process_status(struct procstat *procstat,
			       struct kinfo_proc *proc,
			       const char *exe_path,
			       enum ScanResult res);

/* modes: */
int lsop_basic(void);
int lsop_whitelist(void);
int lsop_stateful(int argc, char *argv[]);

#endif /* LSOP_H defined? */
