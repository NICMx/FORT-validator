#include "common.h"

#include <dirent.h>
#include <errno.h>
#include <time.h>

#include "alloc.h"
#include "config.h"
#include "log.h"

bool
str_starts_with(char const *str, char const *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

bool
str_ends_with(char const *str, char const *suffix)
{
	size_t str_len;
	size_t suffix_len;

	str_len = strlen(str);
	suffix_len = strlen(suffix);
	if (str_len < suffix_len)
		return false;

	return strncmp(str + str_len - suffix_len, suffix, suffix_len) == 0;
}

void
panic_on_fail(int error, char const *function_name)
{
	if (error)
		pr_crit("%s() returned error code %d. This is too critical for a graceful recovery; I must die now.",
		    function_name, error);
}

void
mutex_lock(pthread_mutex_t *lock)
{
	panic_on_fail(pthread_mutex_lock(lock), "pthread_mutex_lock");
}

void
mutex_unlock(pthread_mutex_t *lock)
{
	panic_on_fail(pthread_mutex_unlock(lock), "pthread_mutex_unlock");
}

int
rwlock_read_lock(pthread_rwlock_t *lock)
{
	int error;

	error = pthread_rwlock_rdlock(lock);
	switch (error) {
	case 0:
		return error;
	case EAGAIN:
		pr_op_err_st("There are too many threads; I can't modify the database.");
		return error;
	}

	/*
	 * EINVAL, EDEADLK and unknown nonstandard error codes.
	 * EINVAL, EDEADLK indicate serious programming errors. And it's
	 * probably safest to handle the rest the same.
	 * pthread_rwlock_rdlock() failing like this is akin to `if` failing;
	 * we're screwed badly, so let's just pull the trigger.
	 */
	pr_crit("pthread_rwlock_rdlock() returned error code %d. This is too critical for a graceful recovery; I must die now.",
	    error);
	return EINVAL; /* Warning shutupper */
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
	if (error)
		pr_crit("pthread_rwlock_wrlock() returned error code %d. This is too critical for a graceful recovery; I must die now.",
		    error);
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
	if (error)
		pr_crit("pthread_rwlock_unlock() returned error code %d. This is too critical for a graceful recovery; I must die now.",
		    error);
}

static int
process_file(char const *dir_name, char const *file_name, char const *file_ext,
    int *fcount, foreach_file_cb cb, void *arg)
{
	char const *ext;
	char *fullpath;
	char *tmp;
	int error;

	if (file_ext != NULL) {
		ext = strrchr(file_name, '.');
		/* Ignore file if extension isn't the expected */
		if (ext == NULL || strcmp(ext, file_ext) != 0)
			return 0;
	}

	(*fcount)++; /* Increment the found count */

	/* Get the full file path */
	tmp = pstrdup(dir_name);
	tmp = prealloc(tmp, strlen(tmp) + 1 + strlen(file_name) + 1);

	strcat(tmp, "/");
	strcat(tmp, file_name);
	fullpath = realpath(tmp, NULL);
	if (fullpath == NULL) {
		error = errno;
		pr_op_err("Error getting real path for file '%s' at directory '%s': %s",
		    dir_name, file_name, strerror(error));
		free(tmp);
		return -error;
	}

	error = cb(fullpath, arg);
	free(fullpath);
	free(tmp);
	return error;
}

static int
process_dir_files(char const *location, char const *file_ext, bool empty_err,
    foreach_file_cb cb, void *arg)
{
	DIR *dir_loc;
	struct dirent *dir_ent;
	int found, error;

	dir_loc = opendir(location);
	if (dir_loc == NULL) {
		error = -errno;
		pr_op_err_st("Couldn't open directory '%s': %s", location,
		    strerror(-error));
		goto end;
	}

	errno = 0;
	found = 0;
	while ((dir_ent = readdir(dir_loc)) != NULL) {
		error = process_file(location, dir_ent->d_name, file_ext,
		    &found, cb, arg);
		if (error) {
			pr_op_err("The error was at file %s", dir_ent->d_name);
			goto close_dir;
		}
		errno = 0;
	}
	if (errno) {
		pr_op_err_st("Error reading dir %s", location);
		error = -errno;
	}
	if (!error && found == 0)
		error = (empty_err ?
		    pr_op_err("Location '%s' doesn't have files with extension '%s'",
		    location, file_ext) :
		    pr_op_warn("Location '%s' doesn't have files with extension '%s'",
		    location, file_ext));

close_dir:
	closedir(dir_loc);
end:
	return error;
}

/*
 * If @location points to a file, run @cb on it.
 * If @location points to a directory, run @cb on every child file suffixed
 * @file_ext.
 *
 * TODO (fine) It's weird that @file_ext only filters in directory mode.
 */
int
foreach_file(char const *location, char const *file_ext, bool empty_err,
    foreach_file_cb cb, void *arg)
{
	struct stat attr;
	int error;

	error = stat(location, &attr);
	if (error) {
		error = errno;
		pr_op_err_st("Error reading path '%s': %s", location,
		    strerror(error));
		return error;
	}

	if (S_ISDIR(attr.st_mode) == 0)
		return cb(location, arg);

	return process_dir_files(location, file_ext, empty_err, cb, arg);
}

bool
valid_file_or_dir(char const *location, bool check_file)
{
	struct stat attr;
	bool is_file, is_dir;
	bool result;

	if (stat(location, &attr) == -1) {
		pr_op_err("stat(%s) failed: %s", location, strerror(errno));
		return false;
	}

	is_file = check_file && S_ISREG(attr.st_mode);
	is_dir = S_ISDIR(attr.st_mode);

	result = is_file || is_dir;
	if (!result)
		pr_op_err("'%s' does not seem to be a %s", location,
		    check_file ? "file or directory" : "directory");

	return result;
}

/*
 * Delete @path.
 * If path's parent is now empty, delete parent as well.
 * If parent's parent is now empty, delete parent's parent.
 * And so on.
 *
 * FIXME this should be done by the cache cleaner instead.
 */
int
delete_dir_recursive_bottom_up(char const *path)
{
	char *config_repo;
	char *work_loc, *tmp;
	size_t config_len;
	int error;

	errno = 0;
	if (remove(path) != 0) {
		error = errno;
		pr_val_err("Couldn't delete '%s': %s", path, strerror(error));
		return error;
	}

	config_repo = pstrdup(config_get_local_repository());

	/* Stop dir removal when the work_dir has this length */
	config_len = strlen(config_repo);
	if (config_repo[config_len - 1] == '/')
		config_len--;
	free(config_repo);

	work_loc = pstrdup(path);

	do {
		tmp = strrchr(work_loc, '/');
		if (tmp == NULL)
			break;
		*tmp = '\0';

		/* Stop if the root dir is reached */
		if (strlen(work_loc) == config_len)
			break;

		errno = 0;
		error = rmdir(work_loc);
		if (!error)
			continue; /* Keep deleting up */

		/* Stop if there's content in the dir */
		error = errno;
		if (error == ENOTEMPTY || error == EEXIST)
			break;

		pr_op_err_st("Couldn't delete directory '%s': %s", work_loc,
		    strerror(error));
		goto release_str;
	} while (true);

	free(work_loc);
	return 0;
release_str:
	free(work_loc);
	return error;
}

int
get_current_time(time_t *result)
{
	time_t now;
	int error;

	now = time(NULL);
	if (now == ((time_t) -1)) {
		error = errno;
		pr_val_err("Error getting the current time: %s",
		    strerror(errno));
		return error;
	}

	*result = now;
	return 0;
}
