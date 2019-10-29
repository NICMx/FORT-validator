#include "common.h"

#include <errno.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include <sys/socket.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include <sys/stat.h>

#include "log.h"

int
rwlock_read_lock(pthread_rwlock_t *lock)
{
	int error;

	error = pthread_rwlock_rdlock(lock);
	switch (error) {
	case 0:
		return error;
	case EAGAIN:
		pr_err("There are too many threads; I can't modify the database.");
		return error;
	}

	/*
	 * EINVAL, EDEADLK and unknown nonstandard error codes.
	 * EINVAL, EDEADLK indicate serious programming errors. And it's
	 * probably safest to handle the rest the same.
	 * pthread_rwlock_rdlock() failing like this is akin to `if` failing;
	 * we're screwed badly, so let's just pull the trigger.
	 */
	pr_err("pthread_rwlock_rdlock() returned error code %d. This is too critical for a graceful recovery; I must die now.",
	    error);
	exit(error);
}

void
rwlock_write_lock(pthread_rwlock_t *lock)
{
	int error;

	/*
	 * POSIX says that the only available errors are EINVAL and EDEADLK.
	 * Both of them indicate serious programming errors.
	 */
	error = pthread_rwlock_wrlock(lock);
	if (error) {
		pr_err("pthread_rwlock_wrlock() returned error code %d. This is too critical for a graceful recovery; I must die now.",
		    error);
		exit(error);
	}
}

void
rwlock_unlock(pthread_rwlock_t *lock)
{
	int error;

	/*
	 * POSIX says that the only available errors are EINVAL and EPERM.
	 * Both of them indicate serious programming errors.
	 */
	error = pthread_rwlock_unlock(lock);
	if (error) {
		pr_err("pthread_rwlock_unlock() returned error code %d. This is too critical for a graceful recovery; I must die now.",
		    error);
		exit(error);
	}
}

void
close_thread(pthread_t thread, char const *what)
{
	int error;

	error = pthread_cancel(thread);
	if (error && error != ESRCH)
		pr_crit("pthread_cancel() threw %d on the '%s' thread.",
		    error, what);

	error = pthread_join(thread, NULL);
	if (error)
		pr_crit("pthread_join() threw %d on the '%s' thread.",
		    error, what);
}

static int
process_file(char const *dir_name, char const *file_name, char const *file_ext,
    int *fcount, process_file_cb cb, void *arg)
{
	char *ext, *fullpath, *tmp;
	int error;

	if (file_ext != NULL) {
		ext = strrchr(file_name, '.');
		/* Ignore file if extension isn't the expected */
		if (ext == NULL || strcmp(ext, file_ext) != 0)
			return 0;
	}

	(*fcount)++; /* Increment the found count */

	/* Get the full file path */
	tmp = strdup(dir_name);
	if (tmp == NULL)
		return -pr_errno(errno, "Couldn't create temporal char");

	tmp = realloc(tmp, strlen(tmp) + 1 + strlen(file_name) + 1);
	if (tmp == NULL)
		return -pr_errno(errno, "Couldn't reallocate temporal char");

	strcat(tmp, "/");
	strcat(tmp, file_name);
	fullpath = realpath(tmp, NULL);
	if (fullpath == NULL) {
		free(tmp);
		return -pr_errno(errno,
		    "Error getting real path for file '%s' at dir '%s'",
		    dir_name, file_name);
	}

	error = cb(fullpath, arg);
	free(fullpath);
	free(tmp);
	return error;
}

static int
process_dir_files(char const *location, char const *file_ext,
    process_file_cb cb, void *arg)
{
	DIR *dir_loc;
	struct dirent *dir_ent;
	int found, error;

	dir_loc = opendir(location);
	if (dir_loc == NULL) {
		error = -pr_errno(errno, "Couldn't open dir %s", location);
		goto end;
	}

	errno = 0;
	found = 0;
	while ((dir_ent = readdir(dir_loc)) != NULL) {
		error = process_file(location, dir_ent->d_name, file_ext,
		    &found, cb, arg);
		if (error) {
			pr_err("The error was at file %s", dir_ent->d_name);
			goto close_dir;
		}
		errno = 0;
	}
	if (errno) {
		pr_err("Error reading dir %s", location);
		error = -errno;
	}
	if (!error && found == 0)
		pr_warn("Location '%s' doesn't have files with extension '%s'",
		    location, file_ext);
close_dir:
	closedir(dir_loc);
end:
	return error;
}

int
process_file_or_dir(char const *location, char const *file_ext,
    process_file_cb cb, void *arg)
{
	struct stat attr;
	int error;

	error = stat(location, &attr);
	if (error)
		return pr_errno(errno, "Error reading path '%s'", location);

	if (S_ISDIR(attr.st_mode) == 0)
		return cb(location, arg);

	return process_dir_files(location, file_ext, cb, arg);
}

char const *
addr2str4(struct in_addr const *addr, char *buffer)
{
	return inet_ntop(AF_INET, addr, buffer, INET_ADDRSTRLEN);
}

char const *
addr2str6(struct in6_addr const *addr, char *buffer)
{
	return inet_ntop(AF_INET6, addr, buffer, INET6_ADDRSTRLEN);
}
