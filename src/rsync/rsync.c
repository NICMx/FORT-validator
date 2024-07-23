#include "rsync/rsync.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>

#include "alloc.h"
#include "common.h"
#include "config.h"
#include "log.h"

/*
 * Duplicate parent FDs, to pipe rsync output:
 * - fds[0] = stderr
 * - fds[1] = stdout
 */
static void
duplicate_fds(int fds[2][2])
{
	/* Use the loop to catch interruptions */
	while ((dup2(fds[0][1], STDERR_FILENO) == -1)
		&& (errno == EINTR)) {}
	close(fds[0][1]);
	close(fds[0][0]);

	while ((dup2(fds[1][1], STDOUT_FILENO) == -1)
	    && (errno == EINTR)) {}
	close(fds[1][1]);
	close(fds[1][0]);
}

static void
prepare_rsync(char *args, char const *src, char const *dst, char const *cmpdst)
{
	size_t i = 0;

	/* XXX review */
	args[i++] = config_get_rsync_program();
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
		args[i++] = cmpdst;
	}
	args[i++] = src;
	args[i++] = dst;
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
		close(fds[0][0]);
		close(fds[0][1]);

		pr_op_err_st("Piping rsync stdout: %s", strerror(error));
		return -error;
	}

	return 0;
}

static void
log_buffer(char const *buffer, ssize_t read, int type)
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
		if (type == 0) {
			pr_val_err(PRE_RSYNC "%s", cur);
		} else {
			pr_val_debug(PRE_RSYNC "%s", cur);
		}
		cur = tmp + 1;
	}
	free(cpy);
#undef PRE_RSYNC
}

static int
read_pipe(int fd_pipe[2][2], int type)
{
	char buffer[4096];
	ssize_t count;
	int error;

	while (1) {
		count = read(fd_pipe[type][0], buffer, sizeof(buffer));
		if (count == -1) {
			error = errno;
			if (error == EINTR)
				continue;
			close(fd_pipe[type][0]); /* Close read end */
			pr_val_err("rsync buffer read error: %s",
			    strerror(error));
			return -error;
		}
		if (count == 0)
			break;

		log_buffer(buffer, count, type);
	}

	close(fd_pipe[type][0]); /* Close read end */
	return 0;
}

/*
 * Read the piped output from the child, assures that all pipes are closed on
 * success and on error.
 */
static int
read_pipes(int fds[2][2])
{
	int error;

	/* Won't be needed (sterr/stdout write ends) */
	close(fds[0][1]);
	close(fds[1][1]);

	/* stderr pipe */
	error = read_pipe(fds, 0);
	if (error) {
		/* Close the other pipe pending to read */
		close(fds[1][0]);
		return error;
	}

	/* stdout pipe, always logs to info */
	return read_pipe(fds, 1);
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
	prepare_rsync(&args, src, dst, cmpdst);

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
			close(fork_fds[0][0]);
			close(fork_fds[1][0]);
			close(fork_fds[0][1]);
			close(fork_fds[1][1]);
			return error;
		}

		/* This code is run by us. */
		error = read_pipes(fork_fds);
		if (error)
			kill(child_pid, SIGCHLD); /* Stop the child */

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
