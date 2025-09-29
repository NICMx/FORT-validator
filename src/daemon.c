#include "daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "log.h"

/*
 * Daemonize fort execution. "daemon()" from unistd.h isn't used since it's not
 * portable.
 *
 * This function exits on any error once the first fork is successfully done.
 */
int
daemonize(void)
{
	char *pwd;
	pid_t pid;
	long int fds;
	int error;

	/* Already a daemon, just return */
	if (getppid() == 1)
		return 0;

	/* Get the working dir, the daemon will use (and free) it later */
	pwd = getcwd(NULL, 0);
	if (pwd == NULL) {
		error = errno;
		if (error == ENOMEM)
			enomem_panic();
		pr_err("Cannot get current directory: %s", strerror(error));
		return error;
	}

	pid = fork();
	if (pid < 0) {
		error = errno;
		pr_err("Couldn't fork to daemonize: %s", strerror(error));
		return error;
	}

	/* Terminate parent */
	if (pid > 0)
		exit(0);

	/* Child goes on from here */
	if (setsid() < 0) {
		error = errno;
		pr_err("Couldn't create new session, ending execution: %s",
		    strerror(error));
		exit(error);
	}

	/*
	 * Ignore SIGHUP. SIGCHLD isn't ignored since we still do a fork to
	 * execute rsync; when that's not the case then:
	 *   signal(SIGCHLD, SIG_IGN);
	 * XXX unsafe on multithreaded
	 */
	signal(SIGHUP, SIG_IGN);

	/* Ensure this is not a session leader */
	pid = fork();
	if (pid < 0) {
		error = errno;
		pr_err("Couldn't fork again to daemonize, ending execution: %s",
		    strerror(error));
		exit(error);
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
		error = errno;
		pr_err("Couldn't chdir() daemon, ending execution: %s",
		    strerror(error));
		exit(error);
	}

	free(pwd);
	return 0;
}
