#include "file.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "common.h"
#include "log.h"

/*
 * Will also rewind the file as a side effect.
 * This is currently perfect for calling users.
 */
static int
get_file_size(FILE *file, long int *size)
{
	if (fseek(file, 0L, SEEK_END) == -1)
		return errno ? errno : -EINVAL;
	*size = ftell(file);
	rewind(file);
	return 0;
}

int
file_load(struct validation *state, const char *file_name,
    struct file_contents *fc)
{
	FILE *file;
	long int file_size;
	size_t fread_result;
	int error;

	file = fopen(file_name, "rb");
	if (file == NULL) {
		return pr_errno(state, errno, "Could not open file '%s'",
		    file_name);
	}

	/* TODO if @file is a directory, this returns a very large integer. */
	error = get_file_size(file, &file_size);
	if (error) {
		pr_errno(state, error, "Could not compute the file size of %s",
		    file_name);
		fclose(file);
		return error;
	}

	fc->buffer_size = file_size;
	fc->buffer = malloc(fc->buffer_size);
	if (fc->buffer == NULL) {
		pr_err(state, "Out of memory.");
		fclose(file);
		return -ENOMEM;
	}

	fread_result = fread(fc->buffer, 1, fc->buffer_size, file);
	if (fread_result < fc->buffer_size) {
		error = ferror(file);
		if (error) {
			/*
			 * The manpage doesn't say that the result is an error
			 * code. It literally doesn't say how to obtain the
			 * error code.
			 */
			pr_errno(state, error,
			    "File reading error. Error message (apparently)",
			    file_name);
			free(fc->buffer);
			fclose(file);
			return error;
		}

		/*
		 * As far as I can tell from the man page, feof() cannot return
		 * less bytes that requested like read() does.
		 */
		pr_err(state, "Likely programming error: fread() < file size");
		pr_err(state, "fr:%zu bs:%zu EOF:%d", fread_result,
		    fc->buffer_size, feof(file));
		free(fc->buffer);
		fclose(file);
		return -EINVAL;
	}

	fclose(file);
	return 0;
}

void
file_free(struct file_contents *fc)
{
	free(fc->buffer);
}
