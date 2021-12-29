#include "file.h"

#include <dirent.h> /* readdir(), closedir() */
#include <limits.h> /* realpath() */
#include <stdlib.h> /* malloc(), free(), realloc(), realpath() */
#include <string.h> /* strdup(), strrchr(), strcmp(), strcat(), etc */

#include "config.h"
#include "log.h"

static int
file_get(char const *file_name, FILE **result, struct stat *stat,
    char const *mode)
{
	FILE *file;
	int error;

	file = fopen(file_name, mode);
	if (file == NULL)
		return pr_val_errno(errno, "Could not open file '%s'", file_name);

	if (fstat(fileno(file), stat) == -1) {
		error = pr_val_errno(errno, "fstat(%s) failed", file_name);
		goto fail;
	}
	if (!S_ISREG(stat->st_mode)) {
		error = pr_op_err("%s does not seem to be a file", file_name);
		goto fail;
	}

	*result = file;
	return 0;

fail:
	file_close(file);
	return error;
}

int
file_open(char const *file_name, FILE **result, struct stat *stat)
{
	return file_get(file_name, result, stat, "rb");
}

int
file_write(char const *file_name, FILE **result)
{
	struct stat stat;
	return file_get(file_name, result, &stat, "wb");
}

void
file_close(FILE *file)
{
	if (fclose(file) == -1)
		pr_val_errno(errno, "fclose() failed");
}

int
file_load(char const *file_name, struct file_contents *fc)
{
	FILE *file;
	struct stat stat;
	size_t fread_result;
	int error;

	error = file_open(file_name, &file, &stat);
	if (error)
		return error;

	fc->buffer_size = stat.st_size;
	fc->buffer = malloc(fc->buffer_size);
	if (fc->buffer == NULL) {
		error = pr_enomem();
		goto end;
	}

	fread_result = fread(fc->buffer, 1, fc->buffer_size, file);
	if (fread_result < fc->buffer_size) {
		error = ferror(file);
		if (error) {
			/*
			 * The manpage doesn't say that the result is an error
			 * code. It literally doesn't say how to get an error
			 * code.
			 */
			pr_val_errno(error,
			    "File reading error. Error message (apparently)");
			free(fc->buffer);
			goto end;
		}

		/*
		 * As far as I can tell from the man page, fread() cannot return
		 * less bytes than requested like read() does. It's either
		 * "consumed everything", "EOF reached" or error.
		 */
		pr_op_err("Likely programming error: fread() < file size");
		pr_op_err("fr:%zu bs:%zu EOF:%d", fread_result, fc->buffer_size,
		    feof(file));
		free(fc->buffer);
		error = -EINVAL;
		goto end;
	}

	error = 0;

end:
	file_close(file);
	return error;
}

void
file_free(struct file_contents *fc)
{
	free(fc->buffer);
}

/*
 * Validate @file_name, if it doesn't exist, this function will create it and
 * close it.
 */
bool
file_valid(char const *file_name)
{
	FILE *tmp;
	int error;

	if (file_name == NULL)
		return false;

	error = file_write(file_name, &tmp);
	if (error)
		return false;

	file_close(tmp);
	return true;
}

/*
 * If the modification time is not computable, will return -1.
 * (This mirrors `man 2 time`.)
 *
 * This is because the result of this function is presently always used by
 * libcurl, which prefers a long.
 */
long
file_get_modification_time(char const *luri)
{
	struct stat metadata;

	if (stat(luri, &metadata) != 0)
		return -1;

	if (metadata.st_mtim.tv_sec < 0) {
		pr_val_warn("File modification time is negative: %jd",
		    (intmax_t)metadata.st_mtim.tv_sec);
		return -1;
	}
	if (metadata.st_mtim.tv_sec > LONG_MAX) {
		pr_val_warn("File modification time is too big for libcurl: %ju",
		    /* time_t is not guaranteed to be signed. */
		    (uintmax_t)metadata.st_mtim.tv_sec);
		return -1;
	}

	return metadata.st_mtim.tv_sec;
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
    int (*error_fn)(int error, const char *format, ...))
{
	struct stat attr;
	bool is_file, is_dir;
	bool result;

	if (!check_file && !check_dir)
		pr_crit("Wrong usage, at least one check must be 'true'.");

	if (stat(location, &attr) == -1) {
		if (error_fn != NULL) {
			error_fn(errno, "stat(%s) failed: %s", location,
			    strerror(errno));
		}
		return false;
	}

	is_file = check_file && S_ISREG(attr.st_mode);
	is_dir = check_dir && S_ISDIR(attr.st_mode);

	result = is_file || is_dir;
	if (!result)
		pr_op_err("'%s' does not seem to be a %s", location,
		    (check_file && check_dir) ? "file or directory" :
		    (check_file) ? "file" : "directory");

	return result;
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
 * Ensures all the ancestor directories of @path exist.
 *
 * eg. if @path is "/a/b/c/d.txt", creates a, b and c (if they don't exist).
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
		return pr_val_errno(errno, "Couldn't delete %s", path);

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
