#include "lsop.h"
#include <sys/types.h>
#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <unistd.h>

enum LsopStatefulSource {
	LsopStatefulSource_state,
	LsopStatefulSource_scan
};

struct LsopStatefulFileId {
	uint32_t fsid;		/* filesystem id/mountpoint */
	uint64_t inode;
};

struct LsopStatefulFileInfo {
	/* hash collisions in singly-linked lists */
	struct LsopStatefulFileInfo *fileid_next;
	struct LsopStatefulFileInfo *path_next;

	struct LsopStatefulFileInfo *replacement; /* if such is detected */
	unsigned times_found;			  /* in the filesystem */
	unsigned times_referenced;		  /* from running processes */

	struct LsopStatefulFileId id;
	time_t mtime;
	enum LsopStatefulSource source;
	char path[1];		/* taken into account when malloc'd */
};

struct LsopStateful {
	int state_file_exists;

	/* counters filled by |lsop_basic_scan_mmapped_entry()| */
	struct LsopMmappedState mmap_res;

	enum ScanResult res;	/* ... from |lsop_stateful_scan_process()| */

	/* nonlinear table lookup hasher, as described here:
	 * http://en.wikipedia.org/wiki/Hash_function#Hashing_By_Nonlinear_Table_Lookup */
	uint32_t hasher[256];

	/* two hashtables are built: (1) for filesystem/inode lookup, while
	 * scanning processes, and (2) for path lookup, while enumerating
	 * binaries and shared libraries, to detect replaced files */
	size_t buckets;
	struct LsopStatefulFileInfo **fileid_ht;
	struct LsopStatefulFileInfo **path_ht;
};

static int lsop_stateful_scan_directory_contents(struct LsopStateful *state,
						 const char *dir_path);

static uint32_t
lsop_stateful_hash_opaque(const uint32_t hasher[256],
			  const void *ptr, size_t len)
{
	uint32_t res = 0;
	const uint8_t *p = (const uint8_t*)ptr, *endp = p + len;
	for (; p != endp; ++p) {
		res = res ^ hasher[*p];
	}
	return res;
}


static uint32_t
lsop_stateful_hash_str(const uint32_t hasher[256],
		       const char *s)
{
	uint32_t res = 0;
	for (; *s; ++s) {
		res = res ^ hasher[(unsigned char)*s];
	}
	return res;
}


/* searches in-memory state for given |fileid| */
static struct LsopStatefulFileInfo*
lsop_stateful_find_by_fileid(struct LsopStateful *state,
			     const struct LsopStatefulFileId *fileid)
{
	uint32_t hash = lsop_stateful_hash_opaque(state->hasher,
						  fileid, sizeof *fileid);
	uint32_t bucket = hash % state->buckets;
	struct LsopStatefulFileInfo *it = state->fileid_ht[bucket];
	for (; it; it = it->fileid_next) {
		if (!memcmp(&it->id, fileid, sizeof *fileid)) {
			break;
		}
	}
	return it;
}


/* searches in-memory state for given |path| */
static struct LsopStatefulFileInfo*
lsop_stateful_find_by_path(struct LsopStateful *state,
			   const char *path)
{
	uint32_t hash = lsop_stateful_hash_str(state->hasher, path);
	uint32_t bucket = hash % state->buckets;
	struct LsopStatefulFileInfo *it = state->path_ht[bucket];
	for (; it; it = it->path_next) {
		if (!strcmp(it->path, path)) {
			break;
		}
	}
	return it;
}


/* unconditionally adds |file| to |state|'s hashtables, called when reading a
 * past statefile */
static void
lsop_stateful_append_to_hash(struct LsopStateful *state,
			     struct LsopStatefulFileInfo *file)
{
	uint32_t hash = lsop_stateful_hash_opaque(state->hasher,
						  &file->id,
						  sizeof file->id);
	uint32_t bucket = hash % state->buckets;
	struct LsopStatefulFileInfo **insert = &state->fileid_ht[bucket];
	while (*insert) {
		insert = &(*insert)->fileid_next;
	}
	*insert = file;

	hash = lsop_stateful_hash_str(state->hasher, file->path);
	bucket = hash % state->buckets;
	insert = &state->path_ht[bucket];
	while (*insert) {
		insert = &(*insert)->path_next;
	}
	*insert = file;
}


/* searches |state| for |file|, tracks updates, ignores matches, called, when
 * traversing directories given on the command-line, returns if a reference to
 * |file| is preserved */
static int
lsop_stateful_update_hash(struct LsopStateful *state,
			  struct LsopStatefulFileInfo *file)
{
	struct LsopStatefulFileInfo *existing =
		lsop_stateful_find_by_fileid(state, &file->id);
	if (existing) {
		/* beware: some binaries are hardlinked, for example
		 * /usr/bin/gzip and /usr/bin/gunzip */
		if (existing->mtime == file->mtime) {
			++existing->times_found;
			trace(2, "'%s' found in state (%u/%lu/%u)",
			      file->path,
			      (unsigned)file->id.fsid,
			      (unsigned long)file->id.inode,
			      (unsigned)file->mtime);
			return 0; /* same as existing record in the hash */
		}
	}

	existing = lsop_stateful_find_by_path(state, file->path);
	if (existing) {
		/* found by path, but not by fileid: file have been replaced */
		warnx("'%s' modified (%s): old %u/%lu/%u, new %u/%lu/%u",
		      file->path,
		      existing->path,
		      (unsigned)existing->id.fsid,
		      (unsigned long)existing->id.inode,
		      (unsigned)existing->mtime,
		      (unsigned)file->id.fsid,
		      (unsigned long)existing->id.inode,
		      (unsigned)file->mtime);
		existing->replacement = file;
	} else {
		trace(1, "new file '%s'", file->path);
	}
	lsop_stateful_append_to_hash(state, file);
	return 1;
}


/* fill hashtables from the state file |sflag| */
static int
lsop_stateful_load_state(struct LsopStateful *state)
{
	FILE *in = fopen(sflag, "r");
	if (!in) {
		if (errno == ENOENT) {
			return 0;
		} else {
			warn("fopen: cannot open state file '%s'", sflag);
			return -1;
		}
	}
	trace(1, "loading past state from '%s'", sflag);

	int res = 0, n = 0;
	uint32_t fsid;
	uint64_t inode;
	time_t mtime;
	char line[PATH_MAX + 50];
	while (fgets(line, sizeof line, in)) {
		/* line format: "<fsid>:<inode>:<mtime>:<file-path>\n" */
		const char *p = line, *endp;
		for (fsid = 0; *p && isdigit(*p); ++p) {
			fsid = fsid * 10 + *p - '0';
		}
		if (*p++ != ':') goto bad_fmt;
		for (inode = 0; *p && isdigit(*p); ++p) {
			inode = inode * 10 + *p - '0';
		}
		if (*p++ != ':') goto bad_fmt;
		for (mtime = 0; *p && isdigit(*p); ++p) {
			mtime = mtime * 10 + *p - '0';
		}
		if (*p++ != ':') goto bad_fmt;
		endp = strchr(p, '\n');
		if (!endp) goto bad_fmt;

		size_t path_len = endp - p;
		struct LsopStatefulFileInfo *file = (struct LsopStatefulFileInfo*)calloc(1, sizeof *file + path_len);
		if (!file) {
			errno = ENOMEM;
			warn("cannot read state file '%s'", sflag);
			goto cleanup;
		}
		file->id.fsid = fsid;
		file->id.inode = inode;
		file->mtime = mtime;
		file->source = LsopStatefulSource_state;
		memcpy(file->path, p, path_len);
		file->path[path_len] = '\0';
		trace(2, "loaded '%s' from state (%u/%lu/%u)",
		      file->path,
		      (unsigned)file->id.fsid,
		      (unsigned long)file->id.inode,
		      (unsigned)file->mtime);
		lsop_stateful_append_to_hash(state, file);
		++n;
	}
	state->state_file_exists = 1;
	trace(1, "%u object(s) loaded from state file '%s'",
	      (unsigned)n, sflag);
	goto cleanup;
 bad_fmt:
	warnx("cannot read state file '%s': Bad file format", sflag);
	res = -1;
 cleanup:
	fclose(in);
	return res;
}


static int
lsop_stateful_scan_object_info(struct LsopStateful *state,
			       const char *dir_path,
			       const char *name,
			       int recursive)
{
	trace(3, "examining object '%s/%s'", dir_path, name);
	int rv, res = 0;
	struct stat st;
	if (fflag) {
		rv = stat(name, &st);
	} else {
		/* omit symlinks: most often they point to shared libraries
		 * found during normal directory traversal, anyway */
		rv = lstat(name, &st);
	}
	if (rv == -1) {
		warn("cannot stat file '%s/%s'", dir_path, name);
		return -1;
	}

	if (!S_ISREG(st.st_mode) &&
	    (!S_ISDIR(st.st_mode) || !recursive)) {
		return 0;
	}

	char *abs_path = realpath(name, /*resolved_path*/0);
	if (abs_path) {
		if (S_ISDIR(st.st_mode)) {
			res = lsop_stateful_scan_directory_contents(state, abs_path);
		} else if (S_ISREG(st.st_mode)) {
			const size_t name_len = strlen(abs_path);
			struct LsopStatefulFileInfo *file =
				(struct LsopStatefulFileInfo*)calloc(1, sizeof *file + name_len);
			if (file) {
				file->id.fsid = st.st_dev;
				file->id.inode = st.st_ino;
				file->mtime = st.st_mtim.tv_sec;
				file->source = LsopStatefulSource_scan;
				strcpy(file->path, abs_path);
				trace(2, "dev %u, ino %lu, mtim %u, %s",
				      (unsigned)st.st_dev,
				      (unsigned long)st.st_ino,
				      (unsigned)st.st_mtim.tv_sec,
				      abs_path);
				if (!lsop_stateful_update_hash(state, file)) {
					free(file);
				}
			} else {
				warnx("cannot allocate memory");
				res = -1;
			}
		}
		free(abs_path);
	} else {
		warn("cannot get absolute pathname for '%s/%s'",
		     dir_path, name);
		res = -1;
	}
	return res;
}


/*
 * calls |scan_object_info()| for each file in |dir_path|,
 * invokes |scan_directory_contents()| recursively for each dir;
 * uses |chdir()| for simplicity
 */
static int
lsop_stateful_scan_directory_contents(struct LsopStateful *state,
				      const char *dir_path)
{
	trace(3, "traversing directory '%s'", dir_path);
	int res = 0;
	int cwd_fd = open(".", O_DIRECTORY);
	if (cwd_fd != -1) {
		if (chdir(dir_path) == 0) {
			DIR *dir = opendir(dir_path);
			if (dir) {
				struct dirent *entry;
				while ((entry = readdir(dir)) != 0) {
					if (!strcmp(entry->d_name, ".") ||
					    !strcmp(entry->d_name, "..")) {
						continue;
					}

					if (lsop_stateful_scan_object_info(state, dir_path, entry->d_name, rflag) != 0) {
						res = 1;
					}
				}

				closedir(dir);
			} else {
				warn("opendir: cannot scan directory '%s'", dir_path);
				res = -1;
			}
		} else {
			warn("chdir: cannot change to directory '%s'", dir_path);
			res = -1;
		}
		if (fchdir(cwd_fd) == -1) {
			warn("fchdir: cannot restore working directory");
		}
		close(cwd_fd);
	} else {
		warn("open: cannot open current directory");
		res = -1;
	}
	return res;
}


static void
lsop_stateful_dump_state_by_fileid(const struct LsopStateful *state)
{
	trace(1, "dumping state by fileid from %p", state);
	for (unsigned i = 0; i < state->buckets; ++i) {
		const struct LsopStatefulFileInfo *it = state->fileid_ht[i];
		for (; it; it = it->fileid_next) {
			trace(1, "[%u] '%s' (%u/%lu/%u)",
			      i, it->path,
			      (unsigned)it->id.fsid,
			      (unsigned long)it->id.inode,
			      (unsigned)it->mtime);
		}
	}
}


static void
lsop_stateful_dump_state_by_path(const struct LsopStateful *state)
{
	trace(1, "dumping state by path from %p", state);
	for (unsigned i = 0; i < state->buckets; ++i) {
		const struct LsopStatefulFileInfo *it = state->path_ht[i];
		for (; it; it = it->path_next) {
			trace(1, "[%u] '%s' (%u/%lu/%u)",
			      i, it->path,
			      (unsigned)it->id.fsid,
			      (unsigned long)it->id.inode,
			      (unsigned)it->mtime);
		}
	}
}


static int
lsop_stateful_save_state(const struct LsopStateful *state)
{
	trace(1, "saving state into '%s'", sflag);
	char bak_file[PATH_MAX];
	strcpy(bak_file, sflag);
	strcat(bak_file, "~");
	FILE *out = fopen(bak_file, "w");
	if (!out) {
		warn("open: cannot create file '%s'", bak_file);
		return 1;
	}

	for (unsigned i = 0; i < state->buckets; ++i) {
		const struct LsopStatefulFileInfo *it = state->fileid_ht[i];
		for (; it; it = it->fileid_next) {
			/* line: "<fsid>:<inode>:<mtime>:<file-path>\n" */
			fprintf(out, "%u:%lu:%u:%s\n",
				(unsigned)it->id.fsid,
				(unsigned long)it->id.inode,
				(unsigned)it->mtime,
				it->path);
		}
	}
	if (fclose(out)) {
		warn("write: cannot write file '%s'", bak_file);
		unlink(bak_file);
		return 1;
	}
	if (rename(bak_file, sflag)) {
		warn("rename: cannot rename '%s' to '%s'", bak_file, sflag);
		return 1;
	}
	return 0;
}


static int
lsop_stateful_scan_mmapped_entry(struct procstat *procstat,
				 struct kinfo_proc *proc,
				 struct kinfo_vmentry *map,
				 /*struct LsopStateful*/ void *udata)
{
	struct LsopStateful *state = (struct LsopStateful*)udata;

	(void)procstat; (void)proc;
	struct LsopStatefulFileId id;
	id.fsid = map->kve_vn_fsid;
	id.inode = map->kve_vn_fileid;
	struct LsopStatefulFileInfo *file =
		lsop_stateful_find_by_fileid(state, &id);
	if (file) {
		enum ScanResult res = ScanResult_okay;
		if (file->replacement) {
			trace(1, "pid %u using replaced file '%s'",
			      (unsigned)proc->ki_pid,
			      file->path);
			res = ScanResult_mismatch;
		} else if (!file->times_found) {
			trace(1, "pid %u using missing file '%s'",
			      (unsigned)proc->ki_pid,
			      file->path);
			res = ScanResult_missing;
		}

		++file->times_referenced;
		if (res > state->res) {
			state->res = res;
		}
	} else {
		trace(1, "pid %u using unknown file '%s' (dev %u, inode %lu)",
		      (unsigned)proc->ki_pid,
		      map->kve_path,
		      (unsigned)map->kve_vn_fsid,
		      (unsigned long)map->kve_vn_fileid);
	}
	return 0;
}


static int
lsop_stateful_scan_process (struct procstat *procstat,
			    struct kinfo_proc *proc,
			    const char *exe_path,
			    void *udata)
{
	struct LsopStateful *state = (struct LsopStateful*)udata;
	lsop_reset_mmapped_state(&state->mmap_res);
	int rv = lsop_enum_process_mmappings(procstat, proc,
					     &lsop_stateful_scan_mmapped_entry,
					     state);

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
lsop_stateful(int argc, char *argv[])
{
	struct LsopStateful state;
	memset(&state, 0, sizeof state);
	/* allocate hashtables */
	state.buckets = 32768;
	state.fileid_ht = (struct LsopStatefulFileInfo**)calloc(state.buckets, sizeof *state.fileid_ht);
	state.path_ht = (struct LsopStatefulFileInfo**)calloc(state.buckets, sizeof *state.fileid_ht);
	if (!state.fileid_ht || !state.path_ht) {
		errno = ENOMEM;
		warn("cannot allocate memory");
		return EXIT_FAILURE;
	}

	/* seed hasher */
	for (int i = 0; i < 256; ++i) {
		state.hasher[i] = (uint32_t)rand();
	}

	/* load existing state, if state file exists (no abort on ENOENT) */
	if (lsop_stateful_load_state(&state)) {
		return EXIT_FAILURE;
	}
	//lsop_stateful_dump_state_by_fileid(&state);
	//lsop_stateful_dump_state_by_path(&state);

	for (int i = 0; i < argc; ++i) {
		trace(1, "traversing '%s'", argv[i]);
		lsop_stateful_scan_directory_contents(&state, argv[i]);
	}
	//lsop_stateful_dump_state_by_fileid(&state);
	//lsop_stateful_dump_state_by_path(&state);

	int res = lsop_enum_processes(&lsop_stateful_scan_process, &state);

	//return lsop_stateful_save_state(&state);
	return 0;
}
