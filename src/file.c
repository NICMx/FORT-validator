#include "file.h"

#include <fcntl.h>
#include <ftw.h>

#include "alloc.h"
#include "common.h"
#include "config/mode.h"
#include "log.h"
#include "types/path.h"

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
		error = pr_val_err("'%s' does not seem to be a file.", file_name);
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
		pr_val_err("Could not open file '%s' for writing: %s",
		    file_name, strerror(error));
		*result = NULL;
		return error;
	}

	*result = file;
	return 0;
}

int
file_write_full(char const *path, unsigned char const *content,
    size_t content_len)
{
	FILE *out;
	size_t written;
	int error;

	pr_val_debug("Writing file: %s", path);

	error = file_write(path, "wb", &out);
	if (error)
		return error;

	written = fwrite(content, sizeof(unsigned char), content_len, out);
	file_close(out);

	if (written != content_len)
		return pr_val_err(
		    "Couldn't write file '%s' (error code not available)",
		    path
		);

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
/* XXX needs a rename, because it returns errno. */
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

	if (remove(path) < 0) {
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
	if (remove(fpath) < 0)
		pr_op_warn("Cannot delete %s: %s", fpath, strerror(errno));
	return 0;
}

/* Same as `system("rm -rf <path>")`, but more portable and maaaaybe faster. */
int
file_rm_rf(char const *path)
{
	int error;

	/* TODO (performance) optimize that 32 */
	errno = 0;
	switch (nftw(path, rm, 32, FTW_DEPTH | FTW_PHYS)) {
	case 0:
		return 0; /* Happy path */
	case -1:
		/*
		 * POSIX requires nftw() to set errno,
		 * but the Linux man page doesn't mention it at all...
		 */
		error = errno;
		return error ? error : -1;
	}

	/* This is supposed to be unreachable, but let's not panic. */
	return -1;
}

/* If @force, don't treat EEXIST as an error. */
int
file_mkdir(char const *path, bool force)
{
	int error;

	if (mkdir(path, CACHE_FILEMODE) < 0) {
		error = errno;
		if (!force || error != EEXIST) {
			pr_op_err("Cannot create '%s': %s",
			    path, strerror(error));
			return error;
		}
	}

	return 0;
}

void
cseq_init(struct cache_sequence *seq, char *prefix, bool free_prefix)
{
	seq->prefix = prefix;
	seq->next_id = 0;
	seq->pathlen = strlen(prefix) + 4;
	seq->free_prefix = free_prefix;
}

char *
cseq_next(struct cache_sequence *seq)
{
	char *path;
	int len;

	do {
		path = pmalloc(seq->pathlen);

		// XXX not generic enough
		len = snprintf(path, seq->pathlen, "%s/%lX",
		    seq->prefix, seq->next_id);
		if (len < 0) {
			pr_val_err("Cannot compute new cache path: Unknown cause.");
			return NULL;
		}
		if (len < seq->pathlen) {
			seq->next_id++;
			return path; /* Happy path */
		}

		seq->pathlen++;
		free(path);
	} while (true);
}
