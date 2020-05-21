#define _XOPEN_SOURCE 500

#include "delete_dir_daemon.h"

#include <sys/stat.h>
#include <errno.h>
#include <ftw.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "common.h"
#include "log.h"
#include "random.h"
#include "uri.h"

#define MAX_FD_ALLOWED 20

struct rem_dirs {
	char **arr;
	size_t arr_len;
	size_t arr_set;
};

static int
remove_file(char const *location)
{
	pr_op_debug("Trying to remove file '%s'.", location);
	if (remove(location))
		return pr_op_errno(errno, "Couldn't delete file '%s'", location);
	return 0;
}

static int
remove_dir(char const *location)
{
	pr_op_debug("Trying to remove dir '%s'.", location);
	if (rmdir(location))
		return pr_op_errno(errno, "Couldn't delete directory '%s'",
		    location);
	return 0;
}

static int
traverse(char const *path, struct stat const *sb, int flag, struct FTW *ftwbuf)
{
	/*
	 * FTW_SLN:
	 *   Will never be present since FTW_PHYS flag is utilized
	 */
	switch (flag) {
	case FTW_DP:
		return remove_dir(path);
	case FTW_F:
		return remove_file(path);
	case FTW_DNR:
		return pr_op_err("Can't access '%s', stop deletion.", path);
	case FTW_NS:
		return pr_op_err("Can't get information of '%s', stop deletion.",
		    path);
	case FTW_SL:
		return pr_op_err("Can't delete '%s' since is a symbolic link, stop deletion.",
		    path);
	case FTW_D:
		return pr_op_err("Can't delete '%s' dir before deleting its content.",
		    path);
	default:
		return pr_op_warn("Unknown path flag %d, doing nothing to '%s'.",
		    flag, path);
	}
}

static void *
remove_from_root(void *arg)
{
	struct rem_dirs *root_arg = arg;
	char **dirs_arr;
	size_t len, i;
	int error;

	dirs_arr = root_arg->arr;
	len = root_arg->arr_set;

	/* Release received arg, and detach thread */
	free(root_arg);
	pthread_detach(pthread_self());

	for (i = 0; i < len; i++) {
		error = nftw(dirs_arr[i], traverse, MAX_FD_ALLOWED,
		    FTW_DEPTH|FTW_MOUNT|FTW_PHYS);
		if (error) {
			if (errno)
				pr_op_debug("Error deleting directory '%s', please delete it manually: %s",
				    dirs_arr[i], strerror(errno));
			else
				pr_op_debug("Couldn't delete directory '%s', please delete it manually",
				    dirs_arr[i]);
		}
		/* Release at once, won't be needed anymore */
		free(dirs_arr[i]);
	}

	pr_op_debug("Done removing dirs.");
	free(dirs_arr);
	return NULL;
}

/*
 * Soft/hard error logic utilized, beware to prepare caller:
 * - '> 0' is a soft error
 * - '< 0' is a hard error
 * - '= 0' no error
 */
static int
get_local_path(char const *rcvd, char **result)
{
	struct stat attr;
	struct rpki_uri *uri;
	char *tmp, *local_path;
	size_t tmp_size;
	int error;

	error = uri_create_mixed_str(&uri, rcvd, strlen(rcvd));
	if (error)
		return error != -ENOMEM ? EINVAL : error;

	local_path = strdup(uri_get_local(uri));
	if (local_path == NULL) {
		error = pr_enomem();
		goto release_uri;
	}

	error = stat(local_path, &attr);
	if (error) {
		/* Soft error */
		pr_op_debug("Error reading path '%s' (discarding): %s",
		    local_path, strerror(errno));
		error = errno;
		goto release_local;
	}

	if (!S_ISDIR(attr.st_mode)) {
		/* Soft error */
		pr_op_debug("Path '%s' exists but is not a directory (discarding).",
		    local_path);
		error = ENOTDIR;
		goto release_local;
	}

	/* Assure that root dir ends without '/' */
	tmp_size = strlen(local_path);
	if (strrchr(local_path, '/') == local_path + strlen(local_path) - 1)
		tmp_size--;

	tmp = malloc(tmp_size + 1);
	if (tmp == NULL) {
		error = pr_enomem();
		goto release_local;
	}
	strncpy(tmp, local_path, tmp_size);
	tmp[tmp_size] = '\0';

	free(local_path);
	uri_refput(uri);

	*result = tmp;
	return 0;
release_local:
	free(local_path);
release_uri:
	uri_refput(uri);
	return error;
}

/*
 * Soft/hard error logic utilized, beware to prepare caller:
 * - '> 0' is a soft error
 * - '< 0' is a hard error
 * - '= 0' no error
 */
static int
rename_local_path(char const *rcvd, char **result)
{
	char *tmp;
	long random_sfx;
	size_t rcvd_size, tmp_size;
	int error;

	rcvd_size = strlen(rcvd);
	/* original size + one underscore + hex random val (8 chars) */
	tmp_size = rcvd_size + 1 + (sizeof(RAND_MAX) * 2);
	tmp = malloc(tmp_size + 1);
	if (tmp == NULL)
		return pr_enomem();

	/* Rename the path with a random suffix */
	random_init();
	random_sfx = random_at_most(RAND_MAX);

	snprintf(tmp, tmp_size + 1, "%s_%08lX", rcvd, random_sfx);

	error = rename(rcvd, tmp);
	if (error) {
		free(tmp);
		pr_op_debug("Couldn't rename '%s' to delete it (discarding): %s",
		    rcvd, strerror(errno));
		return errno; /* Soft error */
	}

	*result = tmp;
	return 0;
}

static int
rename_all_roots(struct rem_dirs *rem_dirs, char **src)
{
	char *local_path, *delete_path;
	size_t i;
	int error;

	for (i = 0; i < rem_dirs->arr_len; i++) {
		local_path = NULL;
		error = get_local_path(src[(rem_dirs->arr_len - 1) - i],
		    &local_path);
		if (error < 0)
			return error;
		if (error > 0)
			continue;

		delete_path = NULL;
		error = rename_local_path(local_path, &delete_path);
		free(local_path);
		if (error < 0)
			return error;
		if (error > 0)
			continue;
		rem_dirs->arr[rem_dirs->arr_set++] = delete_path;
	}

	return 0;
}

static int
rem_dirs_create(size_t arr_len, struct rem_dirs **result)
{
	struct rem_dirs *tmp;

	tmp = malloc(sizeof(struct rem_dirs));
	if (tmp == NULL)
		return pr_enomem();

	tmp->arr = calloc(arr_len, sizeof(char *));
	if (tmp->arr == NULL) {
		free(tmp);
		return pr_enomem();
	}

	tmp->arr_len = arr_len;
	tmp->arr_set = 0;

	*result = tmp;
	return 0;
}

static void
rem_dirs_destroy(struct rem_dirs *rem_dirs)
{
	size_t i;

	for (i = 0; i < rem_dirs->arr_set; i++)
		free(rem_dirs->arr[i]);
	free(rem_dirs->arr);
	free(rem_dirs);
}

/*
 * Remove the files listed at @roots array of @roots_len size.
 * 
 * The daemon will be as quiet as possible, since most of its job is done
 * asynchronously. Also, it works on the best possible effort; some errors are
 * treated as "soft" errors, since the directory deletion still doesn't
 * considers the relations (parent-child) at dirs.
 */
int
delete_dir_daemon_start(char **roots, size_t roots_len)
{
	pthread_t thread;
	struct rem_dirs *arg;
	int error;

	arg = NULL;
	error = rem_dirs_create(roots_len, &arg);
	if (error)
		return error;

	error = rename_all_roots(arg, roots);
	if (error) {
		rem_dirs_destroy(arg);
		return error;
	}

	/* Thread arg is released at thread before being detached */
	errno = pthread_create(&thread, NULL, remove_from_root, (void *) arg);
	if (errno) {
		rem_dirs_destroy(arg);
		return pr_op_errno(errno,
		    "Could not spawn the delete dir daemon thread");
	}

	return 0;
}
