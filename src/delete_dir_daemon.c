#define _XOPEN_SOURCE 500

#include "delete_dir_daemon.h"

#include <sys/stat.h>
#include <errno.h>
#include <ftw.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "log.h"
#include "random.h"
#include "uri.h"

#define MAX_FD_ALLOWED 20

static int
remove_file(char const *location)
{
	if (remove(location))
		return pr_errno(errno, "Couldn't delete file '%s'", location);
	return 0;
}

static int
remove_dir(char const *location)
{
	if (rmdir(location))
		return pr_errno(errno, "Couldn't delete directory '%s'",
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
		return pr_err("Can't access '%s', stop deletion.", path);
	case FTW_NS:
		return pr_err("Can't get information of '%s', stop deletion.",
		    path);
	case FTW_SL:
		return pr_err("Can't delete '%s' since is a symbolic link, stop deletion.",
		    path);
	case FTW_D:
		return pr_err("Can't delete '%s' dir before deleting its content.",
		    path);
	default:
		return pr_warn("Unknown path flag %d, doing nothing to '%s'.",
		    flag, path);
	}
}

static void *
remove_from_root(void *arg)
{
	char *root_arg = arg;
	char *root;
	int error;

	pr_debug("Trying to remove dir '%s'.", root_arg);
	root = strdup(root_arg);

	/* Release received arg, and detach thread */
	free(root_arg);
	pthread_detach(pthread_self());

	if (root == NULL) {
		pr_err("Couldn't allocate memory for a string, the directory '%s' won't be deleted, please delete it manually.",
		    root);
		return NULL;
	}

	error = nftw(root, traverse, MAX_FD_ALLOWED,
	    FTW_DEPTH|FTW_MOUNT|FTW_PHYS);
	if (error) {
		if (errno)
			pr_errno(errno, "Error deleting directory '%s', please delete it manually.",
			    root);
		else
			pr_err("Couldn't delete directory '%s', please delete it manually",
			    root);
	}

	pr_debug("Done removing dir '%s'.", root);
	free(root);
	return NULL;
}

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
		return error;

	local_path = strdup(uri_get_local(uri));
	if (local_path == NULL) {
		error = pr_enomem();
		goto release_uri;
	}

	error = stat(local_path, &attr);
	if (error) {
		error = -pr_errno(errno, "Error reading path '%s'", local_path);
		goto release_local;
	}

	if (!S_ISDIR(attr.st_mode)) {
		error = pr_err("Path '%s' exists but is not a directory.",
		    local_path);
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
		return -pr_errno(errno, "Couldn't rename '%s' to delete it.",
		    rcvd);
	}

	*result = tmp;
	return 0;
}

/*
 * Start the @thread that will delete every file under @path, @thread must not
 * be joined, since it's detached. @path will be renamed at the file system.
 */
int
delete_dir_daemon_start(char const *path)
{
	pthread_t thread;
	char *local_path, *delete_path;
	int error;

	error = get_local_path(path, &local_path);
	if (error)
		return error;

	delete_path = NULL;
	error = rename_local_path(local_path, &delete_path);
	if (error) {
		free(local_path);
		return error;
	}

	/* Thread arg is released at thread before being detached */
	errno = pthread_create(&thread, NULL, remove_from_root,
	    (void *) delete_path);
	if (errno) {
		free(delete_path);
		free(local_path);
		return -pr_errno(errno,
		    "Could not spawn the delete dir daemon thread");
	}

	free(local_path);
	return 0;
}
