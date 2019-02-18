#include "log.h"

#include <openssl/bio.h>
#include <openssl/err.h>

#include "thread_var.h"

#define STDOUT stdout
#define STDERR stderr

static unsigned int indent;

static void
pr_indent(FILE *stream)
{
	unsigned int i;
	for (i = 0; i < indent; i++)
		fprintf(stream, "  ");
}

static void
pr_file_name(FILE *stream)
{
#ifndef UNIT_TESTING
	char const *file = fnstack_peek();
	if (file == NULL)
		return;
	fprintf(stream, "%s: ", file);
#endif
}

void
pr_indent_add(void)
{
	indent++;
}

void
pr_indent_rm(void)
{
	if (indent > 0)
		indent--;
	else
		fprintf(STDERR, "Programming error: Too many pr_rm_indent()s.\n");
}

#ifdef DEBUG

void
pr_debug_prefix(void)
{
	fprintf(STDOUT, "DBG: ");
	pr_indent(STDOUT);
}

void
pr_debug(const char *format, ...)
{
	va_list args;

	pr_debug_prefix();

	va_start(args, format);
	vfprintf(STDOUT, format, args);
	va_end(args);
	fprintf(STDOUT, "\n");
}

void
pr_debug_add(const char *format, ...)
{
	va_list args;

	pr_debug_prefix();

	va_start(args, format);
	vfprintf(STDOUT, format, args);
	va_end(args);
	fprintf(STDOUT, "\n");

	pr_indent_add();
}

void
pr_debug_rm(const char *format, ...)
{
	va_list args;

	pr_indent_rm();

	pr_debug_prefix();

	va_start(args, format);
	vfprintf(STDOUT, format, args);
	va_end(args);
	fprintf(STDOUT, "\n");
}

#endif

static void
pr_prefix(char const *level)
{
	fprintf(STDERR, "%s: ", level);
	pr_indent(STDERR);
}

#define PR_PREFIX(level, args) do {		\
	pr_prefix(level);			\
	pr_file_name(STDERR);			\
						\
	va_start(args, format);			\
	vfprintf(STDERR, format, args);		\
	va_end(args);				\
} while (0)

void
pr_info(const char *format, ...)
{
	va_list args;
	PR_PREFIX("INF", args);
	fprintf(STDOUT, "\n");
}

/**
 * Always appends a newline at the end. Always returs 0. (So you can interrupt
 * whatever you're doing without failing validation.)
 */
int
pr_warn(const char *format, ...)
{
	va_list args;
	PR_PREFIX("WRN", args);
	fprintf(STDERR, "\n");
	return 0;
}

/**
 * Always appends a newline at the end. Always returs -EINVAL.
 */
int
pr_err(const char *format, ...)
{
	va_list args;
	PR_PREFIX("ERR", args);
	fprintf(STDERR, "\n");
	return -EINVAL;
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

	PR_PREFIX("ERR", args);

	if (error) {
		fprintf(STDERR, ": %s", strerror(error));
	} else {
		/*
		 * If this function was called, then we need to assume that
		 * there WAS an error; go generic.
		 */
		fprintf(STDERR, ": (Unknown)");
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
	va_list args;
	int error;

	PR_PREFIX("ERR", args);
	fprintf(STDERR, ": ");

	error = ERR_GET_REASON(ERR_peek_last_error());
	if (error) {
		/*
		 * Reminder: This clears the error queue.
		 * BTW: The string format is pretty ugly. Maybe override this.
		 */
		ERR_print_errors_fp(STDERR);
	} else {
		/*
		 * If this function was called, then we need to assume that
		 * there WAS an error; go generic.
		 */
		fprintf(STDERR, "(There are no error messages in the stack.)");
		error = -EINVAL;
	}

	fprintf(STDERR, "\n");
	return error;
}

int
pr_enomem(void)
{
	pr_err("Out of memory.");
	return -ENOMEM;
}

int
pr_crit(const char *format, ...)
{
	va_list args;

	pr_prefix("CRT");
	pr_file_name(STDERR);

	fprintf(STDERR, "Programming error: ");
	va_start(args, format);
	vfprintf(STDERR, format, args);
	va_end(args);
	fprintf(STDERR, "\n");

	return -EINVAL;
}
