#include "file.h"

#include <errno.h>
#include <stdlib.h>
#include "log.h"

static int
file_get(char const *file_name, FILE **result, struct stat *stat,
    char const *mode)
{
	FILE *file;
	int error;

	file = fopen(file_name, mode);
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
			pr_val_err("File reading error. The error message is (apparently) '%s'",
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
