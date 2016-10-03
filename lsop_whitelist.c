#include "lsop.h"
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* a process whitelisted to give false positives */
struct LsopWhitelistProcess {
	struct LsopWhitelistProcess *next;

	char path[PATH_MAX];

	size_t n_anon_mmap_rx_vn_areas;
};

struct LsopWhitelist {
	/* counters filled by |lsop_basic_scan_mmapped_entry()| */
	struct LsopMmappedState mmap_res;

	enum ScanResult res;	/* ... from |lsop_basic_scan_process()| */

	struct LsopWhitelistProcess *head; /* existing stateg */

	FILE *outfile;
};

static void
lsop_whitelist_free(struct LsopWhitelistProcess *head)
{
	struct LsopWhitelistProcess *it = head;
	while (it) {
		struct LsopWhitelistProcess *next = it->next;
		free(it);
		it = next;
	}
}


static int
lsop_whitelist_load_state(struct LsopWhitelistProcess **head)
{
	FILE *fp;
	char buf[PATH_MAX + 20];
	char *p;
	int res = 0;

	if (strcmp(wflag, "-")) {
		fp = fopen(wflag, "r");
		if (!fp) {
			warn("cannot open file '%s'", wflag);
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
		struct LsopWhitelistProcess *proc;

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
				warnx("cannot read '%s': %s",
				      wflag, strerror(ENOMEM));
				res = -1;
				break;
			}
		} else {
			if (strlen(p)) {
				warnx("cannot read '%s': Bad file format", wflag);
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


static const struct LsopWhitelistProcess*
lsop_whitelist_find_proc(const struct LsopWhitelistProcess *head,
			 const char *exe_path)
{
	const struct LsopWhitelistProcess *it = head;
	while (it) {
		if (!strcmp(it->path, exe_path)) {
			return it;
		}
		it = it->next;
	}
	return 0;
}


static int
lsop_whitelist_scan_process(struct procstat *procstat,
			    struct kinfo_proc *proc,
			    const char *exe_path,
			    void *udata)
{
	struct LsopWhitelist *state = (struct LsopWhitelist*)udata;

	const struct LsopWhitelistProcess *opts = 0;
	if (state->head) {
		opts = lsop_whitelist_find_proc(state->head, exe_path);
	}

	lsop_reset_mmapped_state(&state->mmap_res);
	int rv = lsop_enum_process_mmappings(procstat, proc,
					     &lsop_scan_mmapped_entry,
					     &state->mmap_res);

	if (state->mmap_res.n_missing) {
		if (state->outfile) {
			/* remember # of missing entries when instructed to
			 * create a whitelist file */
			fprintf(state->outfile, "%s\t%u\n",
				exe_path,
				(unsigned)state->mmap_res.n_missing);
		}

		if (opts &&
		    opts->n_anon_mmap_rx_vn_areas == state->mmap_res.n_missing) {
			/* ignore whitelisted processes */
			state->mmap_res.n_missing = 0;
		}
	}

	enum ScanResult res = lsop_analyze_result(&state->mmap_res, rv);
	if (res != ScanResult_okay) {
		lsop_print_process_status(procstat, proc, exe_path, res);

		if (res > state->res) {
			state->res = res;
		}
	}
	return 0;
}


int
lsop_whitelist(void)
{
	char temp_path[PATH_MAX];
	struct LsopWhitelist state;
	memset(&state, 0, sizeof state);
	state.res = ScanResult_okay;

	if (wflag &&
	    lsop_whitelist_load_state(&state.head) != 0) {
		/* failed to load whitelist state */
		return EXIT_FAILURE;
	}

	if (cflag) {
		if (strlen(cflag) + 2 > PATH_MAX) {
			warnx("cannot create whitelist '%s': Path name too long", cflag);
			return EXIT_FAILURE;
		}
		/* for better resilience create a temp file and rename to final
		 * file name */
		strcpy(temp_path, cflag);
		strcat(temp_path, "#");
		state.outfile = fopen(temp_path, "w");
		if (!state.outfile) {
			warn("cannot create whitelist '%s'", cflag);
			return EXIT_FAILURE;
		}
	}

	int rv = lsop_enum_processes(&lsop_whitelist_scan_process, &state);

	if (state.outfile) {
		if (fclose(state.outfile) == 0) {
			rv = rename(temp_path, cflag);
			if (rv) {
				warn("cannot rename '%s' to '%s'",
				     temp_path, cflag);
			}
		} else {
			warn("cannot create whitelist '%s'", cflag);
			rv = -1;
		}
	}

	if (state.head) {
		lsop_whitelist_free(state.head);
	}

	if (rv == 0) {
		/* TODO: switch (state.res) ... return ... */
		return state.res;
	}
	return EXIT_FAILURE;
}
