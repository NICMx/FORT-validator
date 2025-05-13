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

static int
write_file(char const *path, void const *bytes, size_t n)
{
	FILE *out;
	int error;

	error = file_write(path, "wb", &out);
	if (error)
		return error;

	errno = 0;
	if (fwrite(bytes, 1, n, out) != n) {
		error = errno;
		if (!error) /* Linux's man page does not mention errno */
			error = -1;
		pr_val_err("Cannot write %s: %s", path, strerror(error));
	}

	file_close(out);
	return error;
}

int
file_write_txt(char const *path, char const *txt)
{
	pr_val_debug("echo 'blah blah' > %s", path);
	return write_file(path, txt, strlen(txt));
}

int
file_write_bin(char const *path, unsigned char const *bytes, size_t n)
{
	pr_val_debug("echo 'beep boop' > %s", path);
	return write_file(path, bytes, n);
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

	fc->buflen = stat.st_size;
	fc->buf = pmalloc(fc->buflen + !is_binary);

	if (!is_binary)
		fc->buf[stat.st_size] = '\0';

	fread_result = fread(fc->buf, 1, fc->buflen, file);
	if (fread_result < fc->buflen) {
		error = ferror(file);
		if (error) {
			/*
			 * The manpage doesn't say that the result is an error
			 * code. It literally doesn't say how to get an error
			 * code.
			 */
			pr_val_err("File reading error. The error message is (possibly) '%s'",
			    strerror(error));
			free(fc->buf);
			goto end;
		}

		/*
		 * As far as I can tell from the man page, fread() cannot return
		 * less bytes than requested like read() does. It's either
		 * "consumed everything", "EOF reached" or error.
		 */
		pr_op_err_st("Likely programming error: fread() < file size (fr:%zu bs:%zu EOF:%d)",
		    fread_result, fc->buflen, feof(file));
		free(fc->buf);
		error = EINVAL;
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
	free(fc->buf);
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

	pr_op_debug("rm -f %s", path);

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
	if (remove(fpath) < 0)
		pr_op_warn("Cannot delete %s: %s", fpath, strerror(errno));
	return 0;
}

/* Same as `system("rm -rf <path>")`, but more portable and maaaaybe faster. */
int
file_rm_rf(char const *path)
{
	int error;

	pr_op_debug("rm -rf %s", path);

	/* TODO (performance) optimize that 32 */
	// XXX In MacOS, this breaks if path is a file.
	if (nftw(path, rm, 32, FTW_DEPTH | FTW_PHYS) < 0) {
		error = errno;
		// XXX This msg is sometimes annoying; maybe defer it
		pr_op_warn("Cannot remove %s: %s", path, strerror(error));
		return error ? error : -1;
	}

	return 0;
}

/* If @force, don't treat EEXIST as an error. */
int
file_mkdir(char const *path, bool force)
{
	int error;

	pr_op_debug("mkdir %s%s", force ? "-f " : "", path);
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
file_ln(char const *oldpath, char const *newpath)
{
	pr_op_debug("ln %s %s", oldpath, newpath);
	if (link(oldpath, newpath) < 0)
		pr_op_warn("Could not hard-link %s to %s: %s",
		    newpath, oldpath, strerror(errno));
}

void
cseq_init(struct cache_sequence *seq, char *prefix, unsigned long id,
    bool free_prefix)
{
	seq->prefix = prefix;
	seq->next_id = id;
	seq->pathlen = strlen(prefix) + 4;
	seq->free_prefix = free_prefix;
}

void
cseq_cleanup(struct cache_sequence *seq)
{
	if (seq->free_prefix)
		free(seq->prefix);
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
