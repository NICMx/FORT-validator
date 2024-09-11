#include "rsync.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>

#include "alloc.h"
#include "common.h"
#include "config.h"
#include "log.h"

#define STDERR_WRITE(fds) fds[0][1]
#define STDOUT_WRITE(fds) fds[1][1]
#define STDERR_READ(fds)  fds[0][0]
#define STDOUT_READ(fds)  fds[1][0]

/*
 * Duplicate parent FDs, to pipe rsync output:
 * - fds[0] = stderr
 * - fds[1] = stdout
 */
static void
duplicate_fds(int fds[2][2])
{
	/* Use the loop to catch interruptions */
	while ((dup2(STDERR_WRITE(fds), STDERR_FILENO) == -1)
		&& (errno == EINTR)) {}
	close(STDERR_WRITE(fds));
	close(STDERR_READ(fds));

	while ((dup2(STDOUT_WRITE(fds), STDOUT_FILENO) == -1)
	    && (errno == EINTR)) {}
	close(STDOUT_WRITE(fds));
	close(STDOUT_READ(fds));
}

static void
prepare_rsync(char **args, char const *src, char const *dst, char const *cmpdst)
{
	size_t i = 0;

	/*
	 * execvp() is not going to tweak those strings;
	 * stop angsting over those casts.
	 */

	/* XXX review */
	args[i++] = (char *)config_get_rsync_program();
#ifdef UNIT_TESTING
	/* Note... --bwlimit does not seem to exist in openrsync */
	args[i++] = "--bwlimit=1K";
	args[i++] = "-vvv";
#else
	args[i++] = "-rtz";
	args[i++] = "--omit-dir-times";
	args[i++] = "--contimeout";
	args[i++] = "20";
	args[i++] = "--max-size";
	args[i++] = "20MB";
	args[i++] = "--timeout";
	args[i++] = "15";
	args[i++] = "--include=*/";
	args[i++] = "--include=*.cer";
	args[i++] = "--include=*.crl";
	args[i++] = "--include=*.gbr";
	args[i++] = "--include=*.mft";
	args[i++] = "--include=*.roa";
	args[i++] = "--exclude=*";
	if (cmpdst) {
		args[i++] = "--compare-dest";
		args[i++] = (char *)cmpdst;
	}
#endif
	args[i++] = (char *)src;
	args[i++] = (char *)dst;
	args[i++] = NULL;
}

__dead static void
handle_child_thread(char **args, int fds[2][2])
{
	/* THIS FUNCTION MUST NEVER RETURN!!! */
	int error;

	duplicate_fds(fds);

	execvp(args[0], args);
	error = errno;
	/* Log directly to stderr, redirected by the pipes */
	fprintf(stderr, "Could not execute the rsync command: %s\n",
	    strerror(error));

	/* https://stackoverflow.com/a/14493459/1735458 */
	exit(-error);
}

static int
create_pipes(int fds[2][2])
{
	int error;

	if (pipe(fds[0]) == -1) {
		error = errno;
		pr_op_err_st("Piping rsync stderr: %s", strerror(error));
		return -error;
	}

	if (pipe(fds[1]) == -1) {
		error = errno;

		/* Close pipe previously created */
		close(STDERR_READ(fds));
		close(STDERR_WRITE(fds));

		pr_op_err_st("Piping rsync stdout: %s", strerror(error));
		return -error;
	}

	return 0;
}

static long
get_current_millis(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		pr_crit("clock_gettime() returned %d", errno);
	return 1000L * now.tv_sec + now.tv_nsec / 1000000L;
}

static void
log_buffer(char const *buffer, ssize_t read, bool is_error)
{
#define PRE_RSYNC "[RSYNC exec]: "
	char *cpy, *cur, *tmp;

	cpy = pmalloc(read + 1);

	strncpy(cpy, buffer, read);
	cpy[read] = '\0';

	/* Break lines to one line at log */
	cur = cpy;
	while ((tmp = strchr(cur, '\n')) != NULL) {
		*tmp = '\0';
		if(strlen(cur) == 0) {
			cur = tmp + 1;
			continue;
		}
		if (is_error)
			pr_val_err(PRE_RSYNC "%s", cur);
		else
			pr_val_debug(PRE_RSYNC "%s", cur);
		cur = tmp + 1;
	}
	free(cpy);
#undef PRE_RSYNC
}

#define DROP_FD(f, fail)		\
	do {				\
		pfd[f].fd = -1;		\
		error |= fail;		\
	} while (0)
#define CLOSE_FD(f, fail)		\
	do {				\
		close(pfd[f].fd);	\
		DROP_FD(f, fail);	\
	} while (0)

/*
 * Consumes (and throws away) all the bytes in read streams @fderr and @fdout,
 * then closes them once they reach end of stream.
 *
 * Returns: ok -> 0, error -> 1, timeout -> 2.
 */
static int
exhaust_read_fds(int fderr, int fdout)
{
	struct pollfd pfd[2];
	int error, nready, f;
	long epoch, delta, timeout;

	memset(&pfd, 0, sizeof(pfd));
	pfd[0].fd = fderr;
	pfd[0].events = POLLIN;
	pfd[1].fd = fdout;
	pfd[1].events = POLLIN;

	error = 0;

	epoch = get_current_millis();
	delta = 0;
	timeout = 1000 * config_get_rsync_transfer_timeout();

	while (1) {
		nready = poll(pfd, 2, timeout - delta);
		if (nready == 0)
			goto timed_out;
		if (nready == -1) {
			error = errno;
			if (error == EINTR)
				continue;
			pr_val_err("rsync bad poll: %s", strerror(error));
			error = 1;
			goto fail;
		}

		for (f = 0; f < 2; f++) {
			if (pfd[f].revents & POLLNVAL) {
				pr_val_err("rsync bad fd: %i", pfd[f].fd);
				DROP_FD(f, 1);

			} else if (pfd[f].revents & POLLERR) {
				pr_val_err("Generic error during rsync poll.");
				CLOSE_FD(f, 1);

			} else if (pfd[f].revents & (POLLIN|POLLHUP)) {
				char buffer[4096];
				ssize_t count;

				count = read(pfd[f].fd, buffer, sizeof(buffer));
				if (count == -1) {
					error = errno;
					if (error == EINTR)
						continue;
					pr_val_err("rsync buffer read error: %s",
					    strerror(error));
					CLOSE_FD(f, 1);
					continue;
				}

				if (count == 0)
					CLOSE_FD(f, 0);
				log_buffer(buffer, count, pfd[f].fd == fderr);
			}
		}

		if (pfd[0].fd == -1 && pfd[1].fd == -1)
			return error; /* Happy path! */

		delta = get_current_millis() - epoch;
		if (delta < 0) {
			pr_val_err("This clock does not seem monotonic. "
			    "I'm going to have to give up this rsync.");
			error = 1;
			goto fail;
		}
		if (delta >= timeout)
			goto timed_out; /* Read took too long */
	}

timed_out:
	pr_val_err("rsync transfer timeout reached");
	error = 2;
fail:	for (f = 0; f < 2; f++)
		if (pfd[f].fd != -1)
			close(pfd[f].fd);
	return error;
}

/*
 * Completely consumes @fds' streams, and closes them.
 *
 * Allegedly, this is a portable way to wait for the child process to finish.
 * (IIRC, waitpid() doesn't do this reliably.)
 */
static int
exhaust_pipes(int fds[2][2])
{
	close(STDERR_WRITE(fds));
	close(STDOUT_WRITE(fds));
	return exhaust_read_fds(STDERR_READ(fds), STDOUT_READ(fds));
}

/* rsync [--compare-dest @cmpdst] @src @dst */
int
rsync_download(char const *src, char const *dst, char const *cmpdst)
{
	char *args[32];
	/* Descriptors to pipe stderr (first element) and stdout (second) */
	int fork_fds[2][2];
	pid_t child_pid;
	unsigned int retries;
	unsigned int i;
	int child_status;
	int error;

	/* Prepare everything for the child exec */
	prepare_rsync(args, src, dst, cmpdst);

	pr_val_info("rsync: %s", src);
	if (log_val_enabled(LOG_DEBUG)) {
		pr_val_debug("Executing rsync:");
		for (i = 0; args[i] != NULL; i++)
			pr_val_debug("    %s", args[i]);
	}

	error = mkdir_p(dst, true, 0777);
	if (error)
		return error;

	retries = 0;
	do {
		child_status = 0;

		error = create_pipes(fork_fds);
		if (error)
			return error;

		/* Flush output (avoid locks between father and child) */
		log_flush();

		/* We need to fork because execvp() magics the thread away. */
		child_pid = fork();
		if (child_pid == 0) {
			/*
			 * This code is run by the child, and should try to
			 * call execvp() as soon as possible.
			 *
			 * Refer to
			 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/fork.html
			 * "{..} to avoid errors, the child process may only
			 * execute async-signal-safe operations until such time
			 * as one of the exec functions is called."
			 */
			handle_child_thread(args, fork_fds);
		}
		if (child_pid < 0) {
			error = errno;
			pr_op_err_st("Couldn't fork to execute rsync: %s",
			   strerror(error));
			/* Close all ends from the created pipes */
			close(STDERR_READ(fork_fds));
			close(STDOUT_READ(fork_fds));
			close(STDERR_WRITE(fork_fds));
			close(STDOUT_WRITE(fork_fds));
			return error;
		}

		/* This code is run by us. */
		error = exhaust_pipes(fork_fds);
		if (error)
			kill(child_pid, SIGTERM); /* Stop the child */

		error = waitpid(child_pid, &child_status, 0);
		do {
			if (error == -1) {
				error = errno;
				pr_op_err_st("The rsync sub-process returned error %d (%s)",
				    error, strerror(error));
				if (child_status > 0)
					break;
				return error;
			}
		} while (0);

		if (WIFEXITED(child_status)) {
			/* Happy path (but also sad path sometimes). */
			error = WEXITSTATUS(child_status);
			pr_val_debug("The rsync sub-process terminated with error code %d.",
			    error);
			if (!error)
				return 0;

			if (retries == config_get_rsync_retry_count()) {
				if (retries > 0)
					pr_val_warn("Max RSYNC retries (%u) reached on '%s', won't retry again.",
					    retries, src);
				return EIO;
			}
			pr_val_warn("Retrying RSYNC '%s' in %u seconds, %u attempts remaining.",
			    src,
			    config_get_rsync_retry_interval(),
			    config_get_rsync_retry_count() - retries);
			retries++;
			sleep(config_get_rsync_retry_interval());
			continue;
		}
		break;
	} while (true);

	if (WIFSIGNALED(child_status)) {
		switch (WTERMSIG(child_status)) {
		case SIGINT:
			pr_op_err_st("RSYNC was user-interrupted. Guess I'll interrupt myself too.");
			break;
		case SIGQUIT:
			pr_op_err_st("RSYNC received a quit signal. Guess I'll quit as well.");
			break;
		case SIGKILL:
			pr_op_err_st("Killed.");
			break;
		default:
			pr_op_err_st("The RSYNC was terminated by a signal [%d] I don't have a handler for. Dunno; guess I'll just die.",
			    WTERMSIG(child_status));
			break;
		}
		return -EINTR; /* Meh? */
	}

	pr_op_err_st("The RSYNC command died in a way I don't have a handler for. Dunno; guess I'll die as well.");
	return -EINVAL;
}
