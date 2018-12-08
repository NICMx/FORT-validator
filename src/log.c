#include "log.h"

#include <openssl/bio.h>
#include <openssl/err.h>

#ifdef DEBUG

#define INDENT_MAX 10
static unsigned int indent;

static void
pr_indent(void)
{
	unsigned int __indent = indent;
	unsigned int i;

//	if (__indent > INDENT_MAX)
//		__indent = INDENT_MAX;

	for (i = 0; i < __indent; i++)
		printf("  ");
}

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
		fprintf(stderr, "Programming error: Too many pr_rm_indent()s.\n");
}

static void
print_debug_prefix(void)
{
	printf("DBG: ");
	pr_indent();
}

#endif

void
pr_debug(const char *format, ...)
{
#ifdef DEBUG
	va_list args;

	print_debug_prefix();

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("\n");
#endif
}

void
pr_debug_add(const char *format, ...)
{
#ifdef DEBUG
	va_list args;

	print_debug_prefix();

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("\n");

	pr_add_indent();
#endif
}

void
pr_debug_rm(const char *format, ...)
{
#ifdef DEBUG
	va_list args;

	pr_rm_indent();

	print_debug_prefix();

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("\n");
#endif
}

/**
 * Always appends a newline at the end.
 */
void
pr_err(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
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

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	if (error) {
		fprintf(stderr, ": %s", strerror(error));
	} else {
		/* We should assume that there WAS an error; go generic. */
		error = -EINVAL;
	}

	fprintf(stderr, "\n");

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
crypto_err(struct validation *state, const char *format, ...)
{
	BIO *bio = validation_stderr(state);
	va_list args;
	int error;

	error = ERR_GET_REASON(ERR_peek_last_error());

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
	return error;
}
