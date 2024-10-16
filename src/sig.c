#include "sig.h"

#include <errno.h>
#ifdef BACKTRACE_ENABLED
#include <execinfo.h>
#endif
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"

/*
 * Ensures libgcc is loaded; otherwise backtrace() might allocate
 * during a signal handler (which is illegal).
 */
static void
setup_backtrace(void)
{
#ifdef BACKTRACE_ENABLED
	void *dummy;
	dummy = NULL;
	backtrace(&dummy, 1);
#endif
}

void
print_stack_trace(void)
{
#ifdef BACKTRACE_ENABLED
	/*
	 * See https://stackoverflow.com/questions/29982643
	 * I went with rationalcoder's answer, because I think not printing
	 * stack traces on segfaults is a nice way of ending up committing
	 * suicide.
	 */
	void *array[64];
	size_t size;
	size = backtrace(array, 64);
	backtrace_symbols_fd(array, size, STDERR_FILENO);
#endif
}

/*
 * THIS IS A SIGNAL HANDLER.
 * Legal functions: https://pubs.opengroup.org/onlinepubs/9799919799/
 */
static void
do_cleanup(int signum)
{
	print_stack_trace();

	/* Trigger default handler */
	signal(signum, SIG_DFL);
	kill(getpid(), signum);
}

/* Remember to enable -rdynamic (See print_stack_trace()). */
void
register_signal_handlers(void)
{
	/* Important: All of these need to terminate by default */
	int const cleanups[] = { SIGSEGV, SIGBUS, 0 };
	struct sigaction action;
	unsigned int i;

	setup_backtrace();

	memset(&action, 0, sizeof(action));
	action.sa_handler = do_cleanup;
	sigfillset(&action.sa_mask);
	action.sa_flags = 0;

	for (i = 0; cleanups[i]; i++)
		if (sigaction(cleanups[i], &action, NULL) < 0)
			pr_op_err("'%s' signal action registration failure: %s",
			    strsignal(cleanups[i]), strerror(errno));

	/*
	 * SIGPIPE can be triggered by any I/O function. libcurl is particularly
	 * tricky:
	 *
	 * > libcurl makes an effort to never cause such SIGPIPEs to trigger,
	 * > but some operating systems have no way to avoid them and even on
	 * > those that have there are some corner cases when they may still
	 * > happen
	 * (Documentation of CURLOPT_NOSIGNAL)
	 *
	 * All SIGPIPE means is "the peer closed the connection for some
	 * reason."
	 * Which is a normal I/O error, and should be handled by the normal
	 * error propagation logic, not by a signal handler.
	 * So, ignore SIGPIPE.
	 *
	 * https://github.com/NICMx/FORT-validator/issues/49
	 */
	action.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &action, NULL) < 0)
		pr_op_err("SIGPIPE action registration failure: %s",
		    strerror(errno));
}
