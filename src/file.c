#include "file.h"

#include <errno.h>
#include <stdlib.h>
#include "log.h"

int
file_open(struct rpki_uri const *uri, FILE **result, struct stat *stat)
{
	FILE *file;
	int error;

	file = fopen(uri->local, "rb");
	if (file == NULL)
		return pr_errno(errno, "Could not open file '%s'", uri->local);

	if (fstat(fileno(file), stat) == -1) {
		error = pr_errno(errno, "fstat(%s) failed", uri->local);
		goto fail;
	}
	if (!S_ISREG(stat->st_mode)) {
		error = pr_err("%s does not seem to be a file", uri->local);
		goto fail;
	}

	*result = file;
	return 0;

fail:
	file_close(file);
	return error;
}

void
file_close(FILE *file)
{
	if (fclose(file) == -1)
		pr_errno(errno, "fclose() failed");
}

int
file_load(struct rpki_uri const *uri, struct file_contents *fc)
{
	FILE *file;
	struct stat stat;
	size_t fread_result;
	int error;

	error = file_open(uri, &file, &stat);
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
			pr_errno(error,
			    "File reading error. Error message (apparently)");
			free(fc->buffer);
			goto end;
		}

		/*
		 * As far as I can tell from the man page, fread() cannot return
		 * less bytes than requested like read() does. It's either
		 * "consumed everything", "EOF reached" or error.
		 */
		pr_err("Likely programming error: fread() < file size");
		pr_err("fr:%zu bs:%zu EOF:%d", fread_result, fc->buffer_size,
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
