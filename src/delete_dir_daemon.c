#define _XOPEN_SOURCE 500

#include "delete_dir_daemon.h"

#include <sys/stat.h>
#include <errno.h>
#include <ftw.h>
#include <unistd.h>
#include "common.h"
#include "log.h"

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
	char const *root = arg;
	struct stat attr;
	int error;

	error = stat(root, &attr);
	if (error) {
		pr_errno(errno, "Error reading path '%s'", root);
		return NULL;
	}

	if (!S_ISDIR(attr.st_mode)) {
		pr_err("Path '%s' exists and is not a directory.", root);
		return NULL;
	}

	error = nftw(root, traverse, MAX_FD_ALLOWED,
	    FTW_DEPTH|FTW_MOUNT|FTW_PHYS);
	if (error) {
		if (errno)
			pr_errno(errno, "Error deleting directory '%s'", root);
		else
			pr_err("Couldn't delete directory '%s'", root);
	}
	return NULL;
}

/*
 * Start the @thread that will delete every file under @path, @thread must be
 * joined.
 */
int
delete_dir_daemon_start(pthread_t *thread, char const *path)
{
	errno = pthread_create(thread, NULL, remove_from_root, (void *) path);
	if (errno)
		return -pr_errno(errno,
		    "Could not spawn the update daemon thread");

	return 0;
}

void
delete_dir_daemon_destroy(pthread_t thread)
{
	close_thread(thread, "Delete dir");
}
