#define _XOPEN_SOURCE 600 /* nftw() */
#define _POSIX_C_SOURCE 200112L /* fileno() */

#include "file.h"

#include <ftw.h>

#include "alloc.h"
#include "log.h"
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
file_write(char const *file_name, FILE **result)
{
	FILE *file;
	int error;

	file = fopen(file_name, "wb");
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
	fc->buffer = pmalloc(fc->buffer_size);

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

static int
rm(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	return (remove(fpath) != 0) ? errno : 0;
}

/* Same as `system("rm -rf <path>")`, but more portable and maaaaybe faster. */
int
file_rm_rf(char const *path)
{
	/* FIXME optimize that 32 */
	return nftw(path, rm, 32, FTW_DEPTH | FTW_PHYS);
}

static int
lsR(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	unsigned int i;

	for (i = 0; i < ftwbuf->level; i++)
		printf("\t");
	printf("%s\n", &fpath[ftwbuf->base]);

	return 0;
}

void
file_ls_R(char const *path)
{
	nftw(path, lsR, 32, FTW_PHYS);
}
