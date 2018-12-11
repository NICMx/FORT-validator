#include "log.h"

#include <openssl/bio.h>
#include <openssl/err.h>

#include "thread_var.h"

#define STDOUT stdout
#define STDERR stderr

#define INDENT_MAX 10
static unsigned int indent;

static void
pr_indent(FILE *stream)
{
	unsigned int __indent = indent;
	unsigned int i;

//	if (__indent > INDENT_MAX)
//		__indent = INDENT_MAX;

	for (i = 0; i < __indent; i++)
		fprintf(stream, "  ");
}

static void
pr_file_name(FILE *stream)
{
	char const *file = fnstack_peek();
	fprintf(stream, "%s: ", (file != NULL) ? file : "(Unknown file)");
}

#ifdef DEBUG

static void
pr_add_indent(void)
{
	indent++;
}

static void
pr_rm_indent(void)
{
	if (indent > 0)
		indent--;
	else
		fprintf(STDERR, "Programming error: Too many pr_rm_indent()s.\n");
}

static void
pr_debug_prefix(void)
{
	fprintf(STDOUT, "DBG: ");
	pr_indent(STDOUT);
}

#endif

void
pr_debug(const char *format, ...)
{
#ifdef DEBUG
	va_list args;

	pr_debug_prefix();

	va_start(args, format);
	vfprintf(STDOUT, format, args);
	va_end(args);
	fprintf(STDOUT, "\n");
#endif
}

void
pr_debug_add(const char *format, ...)
{
#ifdef DEBUG
	va_list args;

	pr_debug_prefix();

	va_start(args, format);
	vfprintf(STDOUT, format, args);
	va_end(args);
	fprintf(STDOUT, "\n");

	pr_add_indent();
#endif
}

void
pr_debug_rm(const char *format, ...)
{
#ifdef DEBUG
	va_list args;

	pr_rm_indent();

	pr_debug_prefix();

	va_start(args, format);
	vfprintf(STDOUT, format, args);
	va_end(args);
	fprintf(STDOUT, "\n");
#endif
}

static void
pr_err_prefix(void)
{
	fprintf(STDERR, "ERR: ");
	pr_indent(STDERR);
}

#define PR_ERR(args) do {			\
	pr_err_prefix();			\
	pr_file_name(STDERR);			\
						\
	va_start(args, format);			\
	vfprintf(STDERR, format, args);		\
	va_end(args);				\
	fprintf(STDERR, "\n");			\
} while (0)

/**
 * Always appends a newline at the end.
 */
void
pr_err(const char *format, ...)
{
	va_list args;
	PR_ERR(args);
}

/**
 * @error fulfills two functions, both of which apply only if it's nonzero:
 *
 * - @error's corresponding generic error message will be appended to the print.
 * - @error's value will be returned. This is for the sake of error code
 *   propagation.
 *
 * If @error is zero, no error message will be appended, and the function will
 * return -EINVAL. (I acknowledge that this looks convoluted at first glance.
 * The purpose is to ensure that this function will propagate an error code even
 * if there is no error code originally.)
 *
 * Always appends a newline at the end.
 */
int
pr_errno(int error, const char *format, ...)
{
	va_list args;

	pr_err_prefix();
	pr_file_name(STDERR);

	va_start(args, format);
	vfprintf(STDERR, format, args);
	va_end(args);

	if (error) {
		fprintf(STDERR, ": %s", strerror(error));
	} else {
		/* We should assume that there WAS an error; go generic. */
		error = -EINVAL;
	}

	fprintf(STDERR, "\n");

	return error;
}

/**
 * This is like pr_err() and pr_errno(), except meant to log an error made
 * during a libcrypto routine.
 *
 * This differs from usual printf-like functions:
 *
 * - It returns the last error code libcrypto threw, not bytes written.
 * - It prints a newline.
 * - Also prints the cryptolib's error message after a colon.
 *   (So don't include periods at the end of @format.)
 *
 * Always appends a newline at the end.
 */
int
crypto_err(const char *format, ...)
{
	struct validation *state;
	BIO *bio;
	bool bio_needs_free;
	char const *file;
	va_list args;
	int error;

	error = ERR_GET_REASON(ERR_peek_last_error());
	bio = NULL;
	bio_needs_free = false;

	state = state_retrieve();
	if (state != NULL)
		bio = validation_stderr(state);
	if (bio == NULL) {
		bio = BIO_new_fp(stderr, BIO_NOCLOSE);
		if (bio == NULL)
			goto trainwreck;
		bio_needs_free = true;
	}

	file = fnstack_peek();
	BIO_printf(bio, "%s: ", (file != NULL) ? file : "(Unknown file)");

	va_start(args, format);
	BIO_vprintf(bio, format, args);
	va_end(args);
	BIO_printf(bio, ": ");

	if (error) {
		/*
		 * Reminder: This clears the error queue.
		 * BTW: The string format is pretty ugly. Maybe override this.
		 */
		ERR_print_errors(bio);
	} else {
		/* We should assume that there WAS an error; go generic. */
		BIO_printf(bio, "(There are no error messages in the stack.)");
		error = -EINVAL;
	}

	BIO_printf(bio, "\n");
	if (bio_needs_free)
		BIO_free_all(bio);
	return error;

trainwreck:
	/* Fall back to behave just like pr_err(). */
	PR_ERR(args);

	pr_err_prefix();
	pr_file_name(STDERR);
	fprintf(STDERR, "(Cannot print libcrypto error: Failed to initialise standard error's BIO.)\n");

	return error ? error : -EINVAL;
}
