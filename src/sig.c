#include "sig.h"

#include <errno.h>
#ifdef BACKTRACE_ENABLED
#include <execinfo.h>
#endif
#include <signal.h>

#include "cache.h"
#include "log.h"
#include "output_printer.h"

volatile bool fort_end = false;

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

static void
pr_err_signal_handler(char const *msg)
{
	write(STDERR_FILENO, msg, strlen(msg));
}

/*
 * THIS IS A SIGNAL HANDLER. Legal functions:
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html
 */
static void
do_cleanup(int signum)
{
	char const *msg = "Terminating signal received.\n";
	struct sigaction action;
	int prev_errno;

	prev_errno = errno;

	write(STDOUT_FILENO, msg, strlen(msg));

	if (signum == SIGSEGV || signum == SIGBUS)
		print_stack_trace();

	cache_atexit();
	output_atexit();

	/*
	 * I still feel like I haven't nailed this code.
	 * The remote possibility that this sigaction() might fail means we're
	 * still required to handle EINTR gracefully after system calls.
	 * So maybe there's no point in even attempting to roll back to the
	 * default handler.
	 */
	memset(&action, 0, sizeof(action));
	action.sa_handler = SIG_DFL;
	sigemptyset(&action.sa_mask);
	if (sigaction(signum, &action, NULL) < 0) {
		int error = errno;
		pr_err_signal_handler("Cannot restore default signal action! ");
		pr_err_signal_handler(strerror(error));
		pr_err_signal_handler("\n");
	} else {
		kill(getpid(), signum);
	}

	errno = prev_errno;
}

/*
 * THIS IS A SIGNAL HANDLER. Legal functions:
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html
 */
static void
sigusr1_handler(int signum)
{
	/*
	 * Nothing.
	 * We want to wake up the main thread's sleep(), but according to its
	 * documentation, that happens automatically.
	 * All we had to do was set up SIGUSR1 so it's neither ignored nor
	 * results in program termination.
	 */
}

/*
 * THIS IS A SIGNAL HANDLER. Legal functions:
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html
 */
static void
sigterm_handler(int signum)
{
	char const *msg = "Received SIGTERM.\n";
	write(STDOUT_FILENO, msg, strlen(msg));

	fort_end = true;
}

/* Remember to enable -rdynamic (See print_stack_trace()). */
void
register_signal_handlers(void)
{
	/* Important: All of these need to terminate by default */
	int const cleanups[] = {
	    SIGFPE, SIGSEGV, SIGBUS, SIGABRT, SIGSYS,	/* 24.2.1 */
	    SIGINT, SIGQUIT, SIGHUP,			/* 24.2.2 */
	    SIGUSR2,					/* 24.2.7 */
	    0
	};
	struct sigaction action;
	unsigned int i;

	setup_backtrace();

	memset(&action, 0, sizeof(action));
	action.sa_handler = do_cleanup;
	sigfillset(&action.sa_mask);
	action.sa_flags = 0;

	for (i = 0; cleanups[i]; i++)
		if (sigaction(cleanups[i], &action, NULL) < 0)
			pr_err("'%s' signal action registration failure: %s",
			    strsignal(cleanups[i]), strerror(errno));

	/* SIGUSR1 handler */
	memset(&action, 0, sizeof(action));
	action.sa_handler = sigusr1_handler;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGUSR1, &action, NULL) < 0)
		pr_err("SIGUSR1 handler registration failure: %s",
		    strerror(errno));

	/* SIGTERM handler */
	memset(&action, 0, sizeof(action));
	action.sa_handler = sigterm_handler;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGTERM, &action, NULL) < 0)
		pr_err("SIGTERM handler registration failure: %s",
		    strerror(errno));

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
	memset(&action, 0, sizeof(action));
	action.sa_handler = SIG_IGN;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGPIPE, &action, NULL) < 0)
		pr_err("SIGPIPE action registration failure: %s",
		    strerror(errno));
}
