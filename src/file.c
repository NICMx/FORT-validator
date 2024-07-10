#include "file.h"

#include <fcntl.h>
#include <ftw.h>
#include <sys/stat.h>

#include "alloc.h"
#include "log.h"
#include "data_structure/path_builder.h"
#include "data_structure/uthash.h"

int
file_open(char const *file_name, FILE **result, struct stat *stat)
{
	FILE *file;
	int error;

	file = fopen(file_name, "rb");
	if (file == NULL) {
		error = errno;
		pr_val_err("Could not open file '%s': %s", file_name,
		    strerror(error));
		return error;
	}

	if (fstat(fileno(file), stat) == -1) {
		error = errno;
		pr_val_err("fstat(%s) failed: %s", file_name, strerror(error));
		goto fail;
	}
	if (!S_ISREG(stat->st_mode)) {
		error = pr_val_err("%s does not seem to be a file", file_name);
		goto fail;
	}

	*result = file;
	return 0;

fail:
	file_close(file);
	return error;
}

int
file_write(char const *file_name, char const *mode, FILE **result)
{
	FILE *file;
	int error;

	file = fopen(file_name, mode);
	if (file == NULL) {
		error = errno;
		pr_val_err("Could not open file '%s': %s", file_name,
		    strerror(error));
		*result = NULL;
		return error;
	}

	*result = file;
	return 0;
}

void
file_close(FILE *file)
{
	if (fclose(file) == -1)
		pr_val_err("fclose() failed: %s", strerror(errno));
}

/*
 * If !is_binary, will append a null character. That's all.
 */
int
file_load(char const *file_name, struct file_contents *fc, bool is_binary)
{
	FILE *file;
	struct stat stat;
	size_t fread_result;
	int error;

	error = file_open(file_name, &file, &stat);
	if (error)
		return error;

	fc->buffer_size = stat.st_size;
	fc->buffer = pmalloc(fc->buffer_size + !is_binary);

	if (!is_binary)
		fc->buffer[stat.st_size] = '\0';

	fread_result = fread(fc->buffer, 1, fc->buffer_size, file);
	if (fread_result < fc->buffer_size) {
		error = ferror(file);
		if (error) {
			/*
			 * The manpage doesn't say that the result is an error
			 * code. It literally doesn't say how to get an error
			 * code.
			 */
			pr_val_err("File reading error. The error message is (possibly) '%s'",
			    strerror(error));
			free(fc->buffer);
			goto end;
		}

		/*
		 * As far as I can tell from the man page, fread() cannot return
		 * less bytes than requested like read() does. It's either
		 * "consumed everything", "EOF reached" or error.
		 */
		pr_op_err_st("Likely programming error: fread() < file size (fr:%zu bs:%zu EOF:%d)",
		    fread_result, fc->buffer_size, feof(file));
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

/* Wrapper for stat(), mostly for the sake of unit test mocking. */
int
file_exists(char const *path)
{
	struct stat meta;
	return (stat(path, &meta) == 0) ? 0 : errno;
}

/*
 * Like remove(), but don't care if the file is already deleted.
 */
int
file_rm_f(char const *path)
{
	int error;

	errno = 0;
	if (remove(path) != 0) {
		error = errno;
		if (error != ENOENT)
			return error;
	}

	return 0;
}

static int
rm(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	pr_op_debug("Deleting %s.", fpath);
	errno = 0;
	return (remove(fpath) != 0) ? errno : 0;
}

/* Same as `system("rm -rf <path>")`, but more portable and maaaaybe faster. */
int
file_rm_rf(char const *path)
{
	/* TODO (performance) optimize that 32 */
	return nftw(path, rm, 32, FTW_DEPTH | FTW_PHYS);
}

/*
 * > 0: exists
 * = 0: !exists
 * < 0: error
 */
static int
dir_exists(char const *path)
{
	struct stat meta;
	int error;

	if (stat(path, &meta) != 0) {
		error = errno;
		if (error == ENOENT)
			return 0;
		pr_op_err_st("stat() failed: %s", strerror(error));
		return -error;
	}

	if (!S_ISDIR(meta.st_mode)) {
		return pr_op_err_st("Path '%s' exists and is not a directory.",
		    path);
	}

	return 1;
}

static int
ensure_dir(char const *path)
{
	int error;

	if (mkdir(path, 0777) != 0) {
		error = errno;
		if (error != EEXIST) {
			pr_op_err_st("Error while making directory '%s': %s",
			    path, strerror(error));
			return error;
		}
	}

	return 0;
}

/* mkdir -p $_path */
/* XXX Maybe also short-circuit by parent? */
int
mkdir_p(char const *_path, bool include_basename)
{
	char *path, *last_slash;
	int i, result = 0;

	path = pstrdup(_path); /* Remove const */

	if (!include_basename) {
		last_slash = strrchr(path, '/');
		if (last_slash == NULL)
			goto end;
		*last_slash = '\0';
	}

	result = dir_exists(path); /* short circuit */
	if (result > 0) {
		result = 0;
		goto end;
	} else if (result < 0) {
		goto end;
	}

	for (i = 1; path[i] != '\0'; i++) {
		if (path[i] == '/') {
			path[i] = '\0';
			result = ensure_dir(path);
			path[i] = '/';
			if (result != 0)
				goto end; /* error msg already printed */
		}
	}
	result = ensure_dir(path);

end:
	free(path);
	return result;
}
