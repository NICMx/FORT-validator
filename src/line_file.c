#include "line_file.h"

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct line_file {
	FILE *file;
	const char *file_name;
	size_t offset;
};

/*
 * @file_name is expected to outlive the lfile.
 */
int
lfile_open(const char *file_name, struct line_file **result)
{
	struct line_file *lfile;
	int error;

	lfile = malloc(sizeof(struct line_file));
	if (lfile == NULL)
		return -ENOMEM;

	lfile->file = fopen(file_name, "r");
	if (lfile->file == NULL) {
		error = errno;
		free(lfile);
		return error;
	}
	lfile->file_name = file_name;
	lfile->offset = 0;

	*result = lfile;
	return 0;
}

void
lfile_close(struct line_file *lf)
{
	if (fclose(lf->file) == -1)
		warn("fclose() failed");
	free(lf);
}

/*
 * On success, places the string in *result.
 * On failure, returns error code.
 * On EOF reached, returns zero but nullifies result.
 *
 * @result is allocated in the heap.
 */
int
lfile_read(struct line_file *lfile, char **result)
{
	char *string;
	size_t alloc_len;
	ssize_t len;
	ssize_t i;
	int error;

	/*
	 * Note to myself:
	 *
	 * getline() is very convoluted. I really don't like it. I'm actually
	 * considering getting rid of it and pulling off something that doesn't
	 * seem like it was designed by an alien, but it doesn't warrant going
	 * that far yet. Do not read its Linux man page; it didn't answer my
	 * questions. Go straight to POSIX instead.
	 *
	 * - If the file is empty, or all that's left is an empty line, it
	 *   (confusingly) returns -1. errno will be 0, feof() should return
	 *   1, ferror() should return 0.
	 * - The fact that it returns the newline in the buffer is puzzling,
	 *   because who the fuck wants that nonsense. You will want to remove
	 *   it, BUT DON'T SWEAT IT IF IT'S NOT THERE, because the last line of
	 *   the file might not be newline-terminated.
	 * - The string WILL be NULL-terminated, but the NULL chara will not be
	 *   included in the returned length. BUT IT'S THERE. Don't worry about
	 *   writing past the allocated space on the last line.
	 * - Newline is `\n` according to POSIX, which is good, because
	 *   RFC 7730 agrees. You will have to worry about `\r`, though.
	 *
	 * Also, the Linux man page claims the following:
	 *
	 *    [The out] buffer should be freed by the user program even if
	 *    getline() failed.
	 *
	 * This... does not exist in the POSIX spec. But it does make sense
	 * because getline is normally meant to be used repeatedly with a
	 * recycled buffer. (free() is a no-op if its argument is NULL so go
	 * nuts.)
	 */

	string = NULL;
	alloc_len = 0;
	len = getline(&string, &alloc_len, lfile->file);

	if (len == -1) {
		error = errno;
		free(string);
		*result = NULL;
		if (ferror(lfile->file)) {
			warnx("Error while reading file: %s",
			    strerror(error));
			return error;
		}
		if (feof(lfile->file))
			return 0;

		error = -EINVAL;
		warnx("Supposedly unreachable code reached. ferror:%d feof:%d",
		    ferror(lfile->file), feof(lfile->file));
		return error;
	}

	lfile->offset += len;

	/*
	 * Make sure that strlen() matches len.
	 * We should make the best out of the fact that we didn't use fgets(),
	 * after all.
	 */
	for (i = 0; i < len; i++) {
		if (string[i] == '\0') {
			error = -EINVAL;
			warnx("File '%s' has an illegal null character in its body. Please remove it.",
			    lfile_name(lfile));
			free(string);
			return error;
		}
	}

	if (len >= 2) {
		if (string[len - 2] == '\r' && string[len - 1] == '\n')
			string[len - 2] = '\0';
	}
	if (len >= 1) {
		if (string[len - 1] == '\n')
			string[len - 1] = '\0';
	}

	*result = string;
	return 0;
}

FILE *
lfile_fd(struct line_file *lfile)
{
	return lfile->file;
}

const char *
lfile_name(struct line_file *lfile)
{
	return lfile->file_name;
}

size_t
lfile_offset(struct line_file *lfile)
{
	return lfile->offset;
}
