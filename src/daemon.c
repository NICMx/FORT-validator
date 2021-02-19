#include "daemon.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "log.h"

/*
 * Daemonize fort execution. The function "daemon()" from unistd header isn't
 * utilized since isn't standardized (too bad).
 *
 * The logs must be sent to syslog before this call, the @log_cb is called to
 * initialize logging after the first fork() call.
 *
 * This function exits on any error once the first fork is successfully done.
 */
int
daemonize(daemon_log_cb log_cb)
{
	char *pwd;
	pid_t pid;
	long int fds;

	/* Already a daemon, just return */
	if (getppid() == 1)
		return 0;

	/* Get the working dir, the daemon will use (and free) it later */
	pwd = getcwd(NULL, 0);
	if (pwd == NULL)
		return pr_enomem();

	pid = fork();
	if (pid < 0)
		return pr_op_errno(errno, "Couldn't fork to daemonize");

	/* Terminate parent */
	if (pid > 0)
		exit(0);

	/* Activate logs */
	log_cb();

	/* Child goes on from here */
	if (setsid() < 0) {
		pr_op_errno(errno,
		    "Couldn't create new session, ending execution");
		exit(errno);
	}

	/*
	 * Ignore SIGHUP. SIGCHLD isn't ignored since we still do a fork to
	 * execute rsync; when that's not the case then:
	 *   signal(SIGCHLD, SIG_IGN);
	 */
	signal(SIGHUP, SIG_IGN);

	/* Assure this is not a session leader */
	pid = fork();
	if (pid < 0) {
		pr_op_errno(errno,
		    "Couldn't fork again to daemonize, ending execution");
		exit(errno);
	}

	/* Terminate parent */
	if (pid > 0)
		exit(0);

	/* Close all descriptors, getdtablesize() isn't portable */
	fds = sysconf(_SC_OPEN_MAX);
	while (fds >= 0) {
		close(fds);
		fds--;
	}

	/* No privileges revoked to create files/dirs */
	umask(0);

	if (chdir(pwd) < 0) {
		pr_op_errno(errno,
		    "Couldn't chdir() of daemon, ending execution");
		exit(errno);
	}

	free(pwd);
	return 0;
}
