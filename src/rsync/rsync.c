#include "rsync/rsync.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h> /* SIGINT, SIGQUIT, etc */
#include <syslog.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "common.h"
#include "log.h"
#include "rpp/rpp_dl_status.h"

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
release_args(char **args, unsigned int size)
{
	unsigned int i;

	/* args[0] wasn't allocated */
	for (i = 1; i < size + 1; i++)
		free(args[i]);
	free(args);
}

static int
prepare_rsync(struct rpki_uri *uri, bool is_file, char ***args, size_t *args_len)
{
	struct string_array const *config_args;
	char **copy_args;
	unsigned int i;

	config_args = config_get_rsync_args(is_file);
	/*
	 * We need to work on a copy, because the config args are immutable,
	 * and we need to add the program name (for some reason) and NULL
	 * elements, and replace $REMOTE and $LOCAL.
	 */
	copy_args = calloc(config_args->length + 2, sizeof(char *));
	if (copy_args == NULL)
		return pr_enomem();

	copy_args[0] = config_get_rsync_program();
	copy_args[config_args->length + 1] = NULL;

	memcpy(copy_args + 1, config_args->array,
	    config_args->length * sizeof(char *));

	for (i = 0; i < config_args->length; i++) {
		if (strcmp(config_args->array[i], "$REMOTE") == 0)
			copy_args[i + 1] = strdup(uri_get_global(uri));
		else if (strcmp(config_args->array[i], "$LOCAL") == 0)
			copy_args[i + 1] = strdup(uri_get_local(uri));
		else
			copy_args[i + 1] = strdup(config_args->array[i]);

		if (copy_args[i + 1] == NULL) {
			release_args(copy_args, i);
			return pr_enomem();
		}
	}

	*args = copy_args;
	*args_len = config_args->length;
	return 0;
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
	if (pipe(fds[0]) == -1)
		return -pr_op_errno(errno, "Piping rsync stderr");
	if (pipe(fds[1]) == -1) {
		/* Close pipe previously created */
		close(fds[0][0]);
		close(fds[0][1]);
		return -pr_op_errno(errno, "Piping rsync stdout");
	}
	return 0;
}

static int
log_buffer(char const *buffer, ssize_t read, int type)
{
#define PRE_RSYNC "[RSYNC exec]: "
	char *cpy, *cur, *tmp;

	cpy = malloc(read + 1);
	if (cpy == NULL)
		return pr_enomem();

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
			pr_val_info(PRE_RSYNC "%s", cur);
		}
		cur = tmp + 1;
	}
	free(cpy);
	return 0;
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
			if (errno == EINTR)
				continue;
			close(fd_pipe[type][0]); /* Close read end */
			return -pr_val_errno(errno, "Reading rsync buffer");
		}
		if (count == 0)
			break;

		error = log_buffer(buffer, count, type);
		if (error)
			return error;
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

/*
 * Downloads the @remote file into the @local path.
 */
static int
do_rsync(struct rpki_uri *uri, bool is_file)
{
	/* Descriptors to pipe stderr (first element) and stdout (second) */
	char **args;
	size_t args_len;
	int fork_fds[2][2];
	pid_t child_pid;
	unsigned int retries;
	unsigned int i;
	int child_status;
	int error;

	/* Prepare everything for the child exec */
	args = NULL;
	args_len = 0;
	error = prepare_rsync(uri, is_file, &args, &args_len);
	if (error)
		return error;

	if (log_val_enabled(LOG_DEBUG)) {
		pr_val_debug("Executing RSYNC:");
		for (i = 0; i < args_len + 1; i++)
			pr_val_debug("    %s", args[i]);
	}

	retries = 0;
	do {
		child_status = 0;
		error = create_dir_recursive(uri_get_local(uri));
		if (error)
			goto release_args;

		error = create_pipes(fork_fds);
		if (error)
			goto release_args;

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
			pr_op_errno(errno, "Couldn't fork to execute rsync");
			error = errno;
			/* Close all ends from the created pipes */
			close(fork_fds[0][0]);
			close(fork_fds[1][0]);
			close(fork_fds[0][1]);
			close(fork_fds[1][1]);
			goto release_args;
		}

		/* This code is run by us. */
		error = read_pipes(fork_fds);
		if (error)
			kill(child_pid, SIGCHLD); /* Stop the child */

		error = waitpid(child_pid, &child_status, 0);
		do {
			if (error == -1) {
				error = errno;
				pr_op_err("The rsync sub-process returned error %d (%s)",
				    error, strerror(error));
				if (child_status > 0)
					break;
				goto release_args;
			}
		} while (0);

		if (WIFEXITED(child_status)) {
			/* Happy path (but also sad path sometimes). */
			error = WEXITSTATUS(child_status);
			pr_val_debug("The rsync sub-process terminated with error code %d.",
			    error);
			if (!error)
				goto release_args;

			if (retries == config_get_rsync_retry_count()) {
				if (retries > 0)
					pr_val_warn("Max RSYNC retries (%u) reached on '%s', won't retry again.",
					    retries, uri_get_global(uri));
				error = EREQFAILED;
				goto release_args;
			}
			pr_val_warn("Retrying RSYNC '%s' in %u seconds, %u attempts remaining.",
			    uri_get_global(uri),
			    config_get_rsync_retry_interval(),
			    config_get_rsync_retry_count() - retries);
			retries++;
			sleep(config_get_rsync_retry_interval());
			continue;
		}
		break;
	} while (true);

	release_args(args, args_len);

	if (WIFSIGNALED(child_status)) {
		switch (WTERMSIG(child_status)) {
		case SIGINT:
			pr_op_err("RSYNC was user-interrupted. Guess I'll interrupt myself too.");
			break;
		case SIGQUIT:
			pr_op_err("RSYNC received a quit signal. Guess I'll quit as well.");
			break;
		case SIGKILL:
			pr_op_err("Killed.");
			break;
		default:
			pr_op_err("The RSYNC was terminated by a signal [%d] I don't have a handler for. Dunno; guess I'll just die.",
			    WTERMSIG(child_status));
			break;
		}
		return -EINTR; /* Meh? */
	}

	pr_op_err("The RSYNC command died in a way I don't have a handler for. Dunno; guess I'll die as well.");
	return -EINVAL;
release_args:
	/* The happy path also falls here */
	release_args(args, args_len);
	return error;
}

/**
 * @is_file: Send true if you're synchronizing a file, false if you're
 * synchronizing a directory.
 * @force: Download regardless of existing download status?
 */
int
rsync_download_files(struct rpki_uri *uri, bool is_file)
{
	int error;

	if (!config_get_rsync_enabled()) {
		/* TODO (aaaa) equivalent RRDP message */
		pr_val_debug("rsync disabled; skipping update.");
		return 0;
	}

	switch (rdsdb_get(uri)) {
	case RDS_NOT_YET:
		break;
	case RDS_SUCCESS:
		pr_val_debug("'%s' was already successfully downloaded in the current validation cycle.",
		    uri_get_global(uri));
		return 0;
	case RDS_ERROR:
		pr_val_err("'%s' was already unsuccessfully downloaded in the current validation cycle; not retrying.",
		    uri_get_global(uri));
		return -EPERM;
	}

	pr_val_debug("Going to RSYNC '%s'.", uri_get_global(uri));

	error = do_rsync(uri, is_file);

	rdsdb_set(uri, error);
	return error;
}
