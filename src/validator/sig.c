#include "validator/sig.h"

#include <errno.h>
#ifdef BACKTRACE_ENABLED
#include <execinfo.h>
#endif
#include <signal.h>

#include "common/log.h"
#include "validator/cache.h"
#include "validator/output_printer.h"

/*
 * Ensures libgcc is loaded; otherwise backtrace() might allocate
 * during a signal handler (which is async-signal-unsafe).
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
pr_inf_safe(char const *msg)
{
	(void)!write(STDOUT_FILENO, msg, strlen(msg));
}

static void
pr_err_safe(char const *msg)
{
	(void)!write(STDERR_FILENO, msg, strlen(msg));
}

static void
reraise(int signum, int errcode)
{
	struct sigaction action;
	int error;

	memset(&action, 0, sizeof(action));
	action.sa_handler = SIG_DFL;
	sigemptyset(&action.sa_mask);
	if (sigaction(signum, &action, NULL) < 0) {
		error = errno;
		pr_err_safe("Cannot restore default signal action! ");
		pr_err_safe(strerror(error));
		pr_err_safe("\n");
		_exit(errcode);
	} else {
		kill(getpid(), signum);
	}
}

/*
 * THIS IS A SIGNAL HANDLER. Legal functions:
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html
 */
static void
handle_program_error_signal(int signum)
{
	pr_inf_safe("Program error signal received.\n");
	print_stack_trace();

	cache_atexit();
	output_atexit();

	reraise(signum, 1);
}

/*
 * THIS IS A SIGNAL HANDLER. Legal functions:
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html
 */
static void
handle_termination_signal(int signum)
{
	pr_inf_safe("Termination signal received.\n");

	cache_atexit();
	output_atexit();

	reraise(signum, 0);
}

/*
 * THIS IS A SIGNAL HANDLER. Legal functions:
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html
 */
static void
handle_sigterm(int signum)
{
	int prev_errno;

	prev_errno = errno;

	pr_inf_safe("SIGTERM received.\n");
	fort_end = true;

	errno = prev_errno;
}

/*
 * THIS IS A SIGNAL HANDLER. Legal functions:
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html
 */
static void
handle_sigusr1(int signum)
{
	/*
	 * Nothing.
	 * We want to wake up the main thread's sleep(), but according to its
	 * documentation, that happens automatically.
	 * All we had to do was set up SIGUSR1 so it's neither ignored nor
	 * results in program termination.
	 */
}

void
register_signal_handlers(void)
{
	int const pes[] = { /* Program error signals */
	    SIGFPE, SIGILL, SIGSEGV, SIGBUS, SIGABRT,
	    SIGIOT, SIGTRAP, SIGSYS, SIGSTKFLT, 0
	};
	int const ts[] = { /* (Regular) termination signals (plus SIGUSR2) */
	    /* XXX SIGHUP should induce config reload on --daemon */
	    SIGINT, SIGQUIT, SIGHUP, SIGUSR2, 0
	};

	struct sigaction action;
	unsigned int i;

	setup_backtrace();

	memset(&action, 0, sizeof(action));
	sigfillset(&action.sa_mask);

	action.sa_handler = handle_program_error_signal;
	for (i = 0; pes[i]; i++)
		if (sigaction(pes[i], &action, NULL) < 0)
			pr_err("'%s' signal action registration failure: %s",
			    strsignal(pes[i]), strerror(errno));

	action.sa_handler = handle_termination_signal;
	for (i = 0; ts[i]; i++)
		if (sigaction(ts[i], &action, NULL) < 0)
			pr_err("'%s' signal action registration failure: %s",
			    strsignal(ts[i]), strerror(errno));

	/* SIGTERM handler */
	memset(&action, 0, sizeof(action));
	action.sa_handler = handle_sigterm;
	if (sigaction(SIGTERM, &action, NULL) < 0)
		pr_err("SIGTERM handler registration failure: %s",
		    strerror(errno));

	/* SIGUSR1 handler */
	action.sa_handler = handle_sigusr1;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGUSR1, &action, NULL) < 0)
		pr_err("SIGUSR1 handler registration failure: %s",
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
	if (sigaction(SIGPIPE, &action, NULL) < 0)
		pr_err("SIGPIPE action registration failure: %s",
		    strerror(errno));
}
