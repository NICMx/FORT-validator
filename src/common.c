#include "common.h"

#include <errno.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include <sys/socket.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include <sys/stat.h>

#include "config.h"
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
		pr_op_err("There are too many threads; I can't modify the database.");
		return error;
	}

	/*
	 * EINVAL, EDEADLK and unknown nonstandard error codes.
	 * EINVAL, EDEADLK indicate serious programming errors. And it's
	 * probably safest to handle the rest the same.
	 * pthread_rwlock_rdlock() failing like this is akin to `if` failing;
	 * we're screwed badly, so let's just pull the trigger.
	 */
	pr_op_err("pthread_rwlock_rdlock() returned error code %d. This is too critical for a graceful recovery; I must die now.",
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
		pr_op_err("pthread_rwlock_wrlock() returned error code %d. This is too critical for a graceful recovery; I must die now.",
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
		pr_op_err("pthread_rwlock_unlock() returned error code %d. This is too critical for a graceful recovery; I must die now.",
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
		return -pr_op_errno(errno, "Couldn't create temporal char");

	tmp = realloc(tmp, strlen(tmp) + 1 + strlen(file_name) + 1);
	if (tmp == NULL)
		return -pr_op_errno(errno, "Couldn't reallocate temporal char");

	strcat(tmp, "/");
	strcat(tmp, file_name);
	fullpath = realpath(tmp, NULL);
	if (fullpath == NULL) {
		free(tmp);
		return -pr_op_errno(errno,
		    "Error getting real path for file '%s' at dir '%s'",
		    dir_name, file_name);
	}

	error = cb(fullpath, arg);
	free(fullpath);
	free(tmp);
	return error;
}

static int
process_dir_files(char const *location, char const *file_ext, bool empty_err,
    process_file_cb cb, void *arg)
{
	DIR *dir_loc;
	struct dirent *dir_ent;
	int found, error;

	dir_loc = opendir(location);
	if (dir_loc == NULL) {
		error = -pr_op_errno(errno, "Couldn't open dir %s", location);
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
		pr_op_err("Error reading dir %s", location);
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

int
process_file_or_dir(char const *location, char const *file_ext, bool empty_err,
    process_file_cb cb, void *arg)
{
	struct stat attr;
	int error;

	error = stat(location, &attr);
	if (error)
		return pr_op_errno(errno, "Error reading path '%s'", location);

	if (S_ISDIR(attr.st_mode) == 0)
		return cb(location, arg);

	return process_dir_files(location, file_ext, empty_err, cb, arg);
}


bool
valid_file_or_dir(char const *location, bool check_file, bool check_dir,
    int (*cb) (int error, const char *format, ...))
{
	FILE *file;
	struct stat attr;
	bool is_file, is_dir;
	bool result;

	if (!check_file && !check_dir)
		pr_crit("Wrong usage, at least one check must be 'true'.");

	result = false;
	file = fopen(location, "rb");
	if (file == NULL) {
		cb(errno, "Could not open location '%s'",
		    location);
		return false;
	}

	if (fstat(fileno(file), &attr) == -1) {
		cb(errno, "fstat(%s) failed", location);
		goto end;
	}

	is_file = check_file && S_ISREG(attr.st_mode);
	is_dir = check_dir && S_ISDIR(attr.st_mode);

	result = is_file || is_dir;
	if (!result)
		pr_op_err("'%s' does not seem to be a %s", location,
		    (check_file && check_dir) ? "file or directory" :
		    (check_file) ? "file" : "directory");

end:
	if (fclose(file) == -1)
		cb(errno, "fclose() failed");
	return result;
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

static int
dir_exists(char const *path, bool *result)
{
	struct stat _stat;
	char *last_slash;

	last_slash = strrchr(path, '/');
	if (last_slash == NULL) {
		/*
		 * Simply because create_dir_recursive() has nothing meaningful
		 * to do when this happens. It's a pretty strange error.
		 */
		*result = true;
		return 0;
	}

	*last_slash = '\0';

	if (stat(path, &_stat) == 0) {
		if (!S_ISDIR(_stat.st_mode)) {
			return pr_op_err("Path '%s' exists and is not a directory.",
			    path);
		}
		*result = true;
	} else if (errno == ENOENT) {
		*result = false;
	} else {
		return pr_op_errno(errno, "stat() failed");
	}

	*last_slash = '/';
	return 0;
}

static int
create_dir(char *path)
{
	int error;

	error = mkdir(path, 0777);

	if (error && errno != EEXIST)
		return pr_op_errno(errno, "Error while making directory '%s'",
		    path);

	return 0;
}

/**
 * Apparently, RSYNC does not like to create parent directories.
 * This function fixes that.
 */
int
create_dir_recursive(char const *path)
{
	char *localuri;
	int i, error;
	bool exist = false;

	error = dir_exists(path, &exist);
	if (error)
		return error;
	if (exist)
		return 0;

	localuri = strdup(path);
	if (localuri == NULL)
		return pr_enomem();

	for (i = 1; localuri[i] != '\0'; i++) {
		if (localuri[i] == '/') {
			localuri[i] = '\0';
			error = create_dir(localuri);
			localuri[i] = '/';
			if (error) {
				/* error msg already printed */
				free(localuri);
				return error;
			}
		}
	}

	free(localuri);
	return 0;
}

static int
remove_file(char const *path)
{
	int error;

	errno = 0;
	error = remove(path);
	if (error)
		return pr_op_errno(errno, "Couldn't delete %s", path);

	return 0;
}

/*
 * Delete parent dirs of @path only if dirs are empty, @path must be a file
 * location and will be deleted first.
 *
 * The algorithm is a bit aggressive, but rmdir() won't delete
 * something unless is empty, so in case the dir still has something in
 * it the cycle is finished.
 */
int
delete_dir_recursive_bottom_up(char const *path)
{
	char *config_repo;
	char *work_loc, *tmp;
	size_t config_len;
	int error;

	error = remove_file(path);
	if (error)
		return error;

	config_repo = strdup(config_get_local_repository());
	if (config_repo == NULL)
		return pr_enomem();

	/* Stop dir removal when the work_dir has this length */
	config_len = strlen(config_repo);
	if (config_repo[config_len - 1] == '/')
		config_len--;
	free(config_repo);

	work_loc = strdup(path);
	if (work_loc == NULL)
		return pr_enomem();

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
		if (errno == ENOTEMPTY || errno == EEXIST)
			break;

		error = pr_op_errno(errno, "Couldn't delete dir %s", work_loc);
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

	now = time(NULL);
	if (now == ((time_t) -1))
		return pr_val_errno(errno, "Error getting the current time");

	*result = now;
	return 0;
}
