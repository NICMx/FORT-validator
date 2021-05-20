#include "debug.h"

#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include "log.h"

/**
 * Important: -rdynamic needs to be enabled, otherwise this does not print
 * function names. See LDFLAGS_DEBUG in Makefile.am.
 * Also: Only non-static functions will be labeled.
 *
 * During a segfault, the first three printed entries are usually not
 * meaningful. Outside of a segfault, the first entry is not meaningful.
 */
void print_stack_trace(void)
{
#define STACK_SIZE 64
	void *array[STACK_SIZE];
	size_t size;
	char **strings;
	size_t i;

	size = backtrace(array, STACK_SIZE);
	strings = backtrace_symbols(array, size);

	pr_op_err("Stack trace:");
	for (i = 0; i < size; i++)
		pr_op_err("  %s", strings[i]);
	pr_op_err("(Stack size was %zu.)", size);

	free(strings);
}

static void
segfault_handler(int thingy)
{
	pr_op_err("Segmentation Fault.");
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
