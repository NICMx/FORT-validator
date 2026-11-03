#include "daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <syslog.h>

#include "log.h"

static int dev_null_fd = -1;

/*
 * This step can be optimized, but doing so is extremely environment-dependent,
 * so I'm not to-doing it for now.
 */
static int
close_nonstandard_fds(void)
{
	struct rlimit rlim;
	int fd;
	int error;

	/*
	 * getrlimit() is POSIX, but if it doesn't compile somewhere,
	 * try sysconf(_SC_OPEN_MAX).
	 */
	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
		error = errno;
		pr_err("getrlimit(RLIMIT_NOFILE): %s", strerror(errno));
		return error;
	}

	for (fd = 3; fd < rlim.rlim_cur; fd++) {
		if (close(fd) == 0) {
			/*
			 * Daemonization happens early enough that it's
			 * reasonable to expect all FDs to be INTENDED to be
			 * closed.
			 * Therefore, this suggests a programming error.
			 */
			pr_crit("File descriptor %d was open", fd);
			continue;
		}
		error = errno;
		if (error != EBADF)
			pr_err("close() failed on file descriptor %d: %s",
			    error, strerror(error));
	}

	return 0;
}

static int
wait_for_grandchild(int notifier[2])
{
	unsigned char buf[1];
	int ret;

	close(notifier[1]);

	ret = read(notifier[0], buf, 1);
	if (ret < 0) {
		ret = errno;
		pr_err("Grandchild read failure: %s", strerror(ret));
		close(notifier[0]);
		return ret;
	}
	if (ret > 0) {
		pr_err("Grandchild wrote bytes in notification pipe.");
		close(notifier[0]);
		return EINVAL;
	}

	pr_trc("Received notification from grandchild; terminating.");
	close(notifier[0]);
	return 0;
}


static int
std2devnull(void)
{
	int error;

	dev_null_fd = open("/dev/null", O_RDWR);

	if (dup2(dev_null_fd, STDIN_FILENO) < 0) {
		error = errno;
		pr_err("dup2(STDIN): %s", strerror(error));
		return error;
	}
	if (dup2(dev_null_fd, STDOUT_FILENO) < 0) {
		error = errno;
		pr_err("dup2(STDOUT): %s", strerror(error));
		return error;
	}
	if (dup2(dev_null_fd, STDERR_FILENO) < 0) {
		error = errno;
		pr_err("dup2(STDERR): %s", strerror(error));
		return error;
	}

	log_silence_std();

	return 0;
}

int
drop_privileges(void)
{
	struct passwd *pwd;
	int error;

	if (getuid() != 0)
		return 0;

	pr_trc("Dropping privileges (switching to 'fort' user)...");

	errno = 0;
	pwd = getpwnam("fort");
	if (!pwd) {
		error = errno;
		if (!error)
			error = ENOENT;
		pr_err("Cannot retrieve uid and gid of user 'fort': %s",
		    strerror(error));
		return error;
	}

	if (setgid(pwd->pw_gid) < 0) {
		error = errno;
		pr_err("Cannot switch to the 'fort' group: %s",
		    strerror(error));
		return error;
	}
	if (setuid(pwd->pw_gid) < 0) {
		error = errno;
		pr_err("Cannot switch to the 'fort' user: %s",
		    strerror(error));
		return error;
	}

	if (setuid(0) == 0) {
		pr_err("I regained root privileges after dropping them; "
		    "something has gone wrong.");
		return EINVAL;
	}

	pr_trc("Privileges dropped.");
	return 0;
}

/*
 * Daemonize fort execution, "old style." In Linux, this is generally explained
 * in daemon(7).
 *
 * TODO (fine) add new style option, I guess
 *
 * Important:
 *
 * - This is supposed to reset signals for some reason, so initialize signal
 *   handlers after this function.
 * - This closes all file descriptors above 3. In particular, this means that
 *   logging has to be initialized after this function.
 */
init_verdict
daemonize(void)
{
	pid_t pid;
	int notifier[2];

	/* Already a daemon, just return */
	if (getppid() == 1)
		return IV_CONTINUE;

	pr_trc("Daemonizing...");

	/* 1. Close nonstandard file descriptors */
	if (close_nonstandard_fds() != 0)
		return IV_FAIL;

	/* 2. Reset signal handlers to defaults */
	/* Nothing to do; signals will be set up later */

	/* 3. Reset the signal mask */
	/* Nothing to do; signals will be set up later */

	/* 4. Sanitize the environment block */
	/* Nothing to do. I think. */

	/* 14a. Create channel to grandchild */
	if (pipe(notifier) < 0) {
		pr_err("Cannot create pipe: %s", strerror(errno));
		return IV_FAIL;
	}

	/*
	 * 5. Become a child process.
	 * The point is to move us (ie. the child) to the background.
	 */
	pid = fork();
	if (pid < 0) {
		pr_err("Couldn't fork to daemonize: %s", strerror(errno));
		close(notifier[0]);
		close(notifier[1]);
		return IV_FAIL;
	}
	if (pid > 0) {
		/* 14b. Wait until grandchild is fully initialized */
		return wait_for_grandchild(notifier) ? IV_FAIL : IV_DONE;
	}

	close(notifier[0]);

	/*
	 * 6. Create new session, move into it.
	 * This disassociates us from the controlling terminal.
	 */
	if (setsid() < 0) {
		pr_err("Couldn't create new session, ending execution: %s",
		    strerror(errno));
		close(notifier[1]);
		return IV_FAIL;
	}

	/*
	 * pcarana left this. I still don't know why.
	 * I suspect it has to do with SIGHUP being traditionally used for
	 * daemon configuration reloading. But since we've never implemented it
	 * that way, SIG_IGN would prevents us from dying in case a distracted
	 * admin tries to reload config.
	 * TODO (fine) But ignoring is not a great solution either... maybe
	 * implement reloadable configuration.
	 */
	/* signal(SIGHUP, SIG_IGN); */

	/*
	 * 7. Fork again.
	 * setsid() made us the session leader, which we do not want.
	 * This second fork undoes it.
	 * Not being a leader ensures we will not be able to get another
	 * controlling terminal later.
	 */
	pid = fork();
	if (pid < 0) {
		pr_err("Couldn't fork again to daemonize, ending execution: %s",
		    strerror(errno));
		close(notifier[1]);
		return IV_FAIL;
	}

	/*
	 * 8. Drop the first child.
	 * This ensures our parent is PID 1.
	 */
	if (pid > 0) {
		close(notifier[1]);
		return IV_DONE;
	}

	/*
	 * 9. Drop standard interactivity (connect the standard streams to
	 *    /dev/null).
	 * This nullifies standard reads and writes, without turning them into
	 * errors.
	 * The latter is probably the reason why we didn't close them during 1.
	 */
	if (std2devnull() != 0) {
		close(notifier[1]);
		return IV_FAIL;
	}

	/* 10. Reset the umask. */
	if (umask(0) != 0)
		pr_crit("File mode creation mask was not zero");

	/* 11. cd / */
	/*
	 * Denied; we need to cd to the cachedir (done later by the cache code)
	 * because we actually want those relative paths, and also because we
	 * want the cachedir locked.
	 */

	/* 12. Write PID to file */
	/*
	 * Offloaded to the cache code, as it already has a lockfile with the
	 * PID in it.
	 */

	/* 13. Drop privileges */
	/* Postponed; needs to happen regardless of daemonization */

	/* 14c. Release grandparent */
	if (close(notifier[1]) < 0)
		pr_err("Might have not notified parent: %s", strerror(errno));;

	pr_trc("Daemonized.");
	return IV_CONTINUE;
}

/* THIS FUNCTION CAN BE CALLED FROM A SIGNAL HANDLER. */
void
daemon_teardown(void)
{
	if (dev_null_fd != -1) {
		close(dev_null_fd);
		dev_null_fd = -1;
	}
}
