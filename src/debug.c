#include "debug.h"

#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * Important: -rdynamic needs to be enabled, otherwise this does not print
 * function names. See rpki_validator_LDFLAGS in Makefile.am.
 * Also: Only non-static functions will be labeled.
 *
 * I think that the first three printed entries are usually not meaningful.
 */
void print_stack_trace(void)
{
	void *array[256];
	size_t size;
	char **strings;
	size_t i;

	size = backtrace(array, 256);
	strings = backtrace_symbols(array, size);

	fprintf(stderr, "Stack trace:\n");
	for (i = 0; i < size; i++)
		fprintf(stderr, "  %s\n", strings[i]);
	fprintf(stderr, "(Stack size was %zu.)\n", size);

	free(strings);
}

static void
segfault_handler(int thingy)
{
	fprintf(stderr, "Segmentation Fault. ");
	print_stack_trace();
	exit(1);
}

/**
 * If you get a Segmentation Fault after calling this, the stack trace will be
 * automatically printed in standard error.
 * Remember to enable -rdynamic (See print_stack_trace()).
 */
void
print_stack_trace_on_segfault(void)
{
	struct sigaction handler;

	handler.sa_handler = segfault_handler;
	sigemptyset(&handler.sa_mask);
	handler.sa_flags = 0;
	sigaction(SIGSEGV, &handler, NULL);
}
