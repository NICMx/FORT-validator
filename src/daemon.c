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

#include <syslog.h>

#include "log.h"

/*
 * Daemonize fort execution. "daemon()" from unistd.h isn't used since it's not
 * portable.
 */
init_verdict
daemonize(void)
{
	pid_t pid;
	long int fds;
	int error;

	/* Already a daemon, just return */
	if (getppid() == 1)
		return IV_CONTINUE;

	pr_trc("Daemonizing...");

	pid = fork();
	if (pid < 0) {
		pr_err("Couldn't fork to daemonize: %s", strerror(errno));
		return IV_FAIL;
	}

	/* Terminate parent */
	if (pid > 0)
		return IV_DONE;

	/* Child goes on from here */
	if (setsid() < 0) {
		pr_err("Couldn't create new session, ending execution: %s",
		    strerror(errno));
		return IV_FAIL;
	}

	/*
	 * TODO
	 * I suspect this has to do with SIGHUP being traditionally used for
	 * daemon configuration reloading. But since we've never implemented it
	 * that way, SIG_IGN would prevents us from dying in case a distracted
	 * admin tries to reload config.
	 * But ignoring is not a great solution either... maybe I should
	 * implement reloadable configuration.
	 */
	/* signal(SIGHUP, SIG_IGN); */

	/* Ensure this is not a session leader */
	pid = fork();
	if (pid < 0) {
		pr_err("Couldn't fork again to daemonize, ending execution: %s",
		    strerror(errno));
		return IV_FAIL;
	}

	/* Terminate parent */
	if (pid > 0)
		return IV_DONE;

	/* Close all descriptors, getdtablesize() isn't portable */
	/* XXX WTF is this? It's closing FDs 0-1024 in my env */
	fds = sysconf(_SC_OPEN_MAX);
	while (fds >= 0) {
		close(fds);
		fds--;
	}

	/* No privileges revoked to create files/dirs */
	/* XXX WTF? 0 & 0777? */
	umask(0);

	pr_trc("Daemonized.");
	return IV_CONTINUE;
}
