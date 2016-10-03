#include "lsop.h"
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>

struct LsopBasic {
	/* counters filled by |lsop_basic_scan_mmapped_entry()| */
	struct LsopMmappedState mmap_res;

	enum ScanResult res;	/* ... from |lsop_basic_scan_process()| */
};

static int
lsop_basic_scan_process(struct procstat *procstat,
			struct kinfo_proc *proc,
			const char *exe_path,
			void *udata)
{
	struct LsopBasic *state = (struct LsopBasic*)udata;
	lsop_reset_mmapped_state(&state->mmap_res);
	int rv = lsop_enum_process_mmappings(procstat, proc,
					     &lsop_scan_mmapped_entry,
					     &state->mmap_res);

	enum ScanResult res = lsop_analyze_result(&state->mmap_res, rv);
	if (res != ScanResult_okay) {
		lsop_print_process_status(procstat, proc, exe_path, res);

		/* exit code is a single value, therefore only single state can
		 * be propagandated; since options in |ScanResult| are ordered
		 * by importance (having confirmed miss is more important than
		 * occasional error) operator greater-than would suffice */
		if (res > state->res) {
			state->res = res;
		}
	}
	return 0;
}


int
lsop_basic(void)
{
	struct LsopBasic state;
	memset(&state, 0, sizeof state);
	state.res = ScanResult_okay;
	if (lsop_enum_processes(&lsop_basic_scan_process, &state) == 0) {
		/* TODO: switch (state.res) ... return ... */
		return state.res;
	}
	return EXIT_FAILURE;
}
