#include "rsync.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h> /* SIGINT, SIGQUIT, etc */
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "common.h"
#include "config.h"
#include "log.h"
#include "reqs_errors.h"
#include "str_token.h"
#include "thread_var.h"

struct uri {
	struct rpki_uri *uri;
	SLIST_ENTRY(uri) next;
};

/** URIs that we have already downloaded. */
SLIST_HEAD(uri_list, uri);

/* static char const *const RSYNC_PREFIX = "rsync://"; */

int
rsync_create(struct uri_list **result)
{
	struct uri_list *visited_uris;

	visited_uris = malloc(sizeof(struct uri_list));
	if (visited_uris == NULL)
		return pr_enomem();

	SLIST_INIT(visited_uris);

	*result = visited_uris;
	return 0;
}

void
rsync_destroy(struct uri_list *list)
{
	struct uri *uri;

	while (!SLIST_EMPTY(list)) {
		uri = SLIST_FIRST(list);
		SLIST_REMOVE_HEAD(list, next);
		uri_refput(uri->uri);
		free(uri);
	}
	free(list);
}

/*
 * Returns true if @ancestor an ancestor of @descendant, or @descendant itself.
 * Returns false otherwise.
 */
static bool
is_descendant(struct rpki_uri *ancestor, struct rpki_uri *descendant)
{
	struct string_tokenizer ancestor_tokenizer;
	struct string_tokenizer descendant_tokenizer;

	string_tokenizer_init(&ancestor_tokenizer, uri_get_global(ancestor),
	    uri_get_global_len(ancestor), '/');
	string_tokenizer_init(&descendant_tokenizer, uri_get_global(descendant),
	    uri_get_global_len(descendant), '/');

	if (config_get_rsync_strategy() == RSYNC_STRICT)
		return strcmp(uri_get_global(ancestor),
		    uri_get_global(descendant)) == 0;

	do {
		if (!string_tokenizer_next(&ancestor_tokenizer))
			return true;
		if (!string_tokenizer_next(&descendant_tokenizer))
			return false;
		if (!token_equals(&ancestor_tokenizer, &descendant_tokenizer))
			return false;
	} while (true);
}

/*
 * Returns whether @uri has already been rsync'd during the current validation
 * run.
 */
static bool
is_already_downloaded(struct rpki_uri *uri, struct uri_list *visited_uris)
{
	struct uri *cursor;

	/* TODO (next iteration) this is begging for a radix trie. */
	SLIST_FOREACH(cursor, visited_uris, next)
		if (is_descendant(cursor->uri, uri))
			return true;

	return false;
}

static int
mark_as_downloaded(struct rpki_uri *uri, struct uri_list *visited_uris)
{
	struct uri *node;

	node = malloc(sizeof(struct uri));
	if (node == NULL)
		return pr_enomem();

	node->uri = uri;
	uri_refget(uri);

	SLIST_INSERT_HEAD(visited_uris, node, next);

	return 0;
}

static int
handle_strict_strategy(struct rpki_uri *requested_uri,
    struct rpki_uri **rsync_uri)
{
	*rsync_uri = requested_uri;
	uri_refget(requested_uri);
	return 0;
}

static int
handle_root_strategy(struct rpki_uri *src, struct rpki_uri **dst)
{
	char const *global;
	size_t global_len;
	unsigned int slashes;
	size_t i;

	global = uri_get_global(src);
	global_len = uri_get_global_len(src);
	slashes = 0;

	for (i = 0; i < global_len; i++) {
		if (global[i] == '/') {
			slashes++;
			if (slashes == 4)
				return uri_create_rsync_str(dst, global, i);
		}
	}

	*dst = src;
	uri_refget(src);
	return 0;
}

static int
get_rsync_uri(struct rpki_uri *requested_uri, bool is_ta,
    struct rpki_uri **rsync_uri)
{
	switch (config_get_rsync_strategy()) {
	case RSYNC_ROOT:
		return handle_root_strategy(requested_uri, rsync_uri);
	case RSYNC_ROOT_EXCEPT_TA:
		return is_ta
		    ? handle_strict_strategy(requested_uri, rsync_uri)
		    : handle_root_strategy(requested_uri, rsync_uri);
	case RSYNC_STRICT:
		return handle_strict_strategy(requested_uri, rsync_uri);
	default:
		break;
	}

	pr_crit("Invalid rsync strategy: %u", config_get_rsync_strategy());
}

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
prepare_rsync(struct rpki_uri *uri, bool is_ta, char ***args, size_t *args_len)
{
	struct string_array const *config_args;
	char **copy_args;
	unsigned int i;

	config_args = config_get_rsync_args(is_ta);
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

static void
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
	exit(error);
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

static void
log_buffer(char const *buffer, ssize_t read, int type, bool log_operation)
{
#define PRE_RSYNC "[RSYNC exec]: "
	char *cpy, *cur, *tmp;

	cpy = malloc(read + 1);
	if (cpy == NULL) {
		pr_enomem();
		return;
	}
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
			if (log_operation)
				pr_op_err(PRE_RSYNC "%s", cur);
			pr_val_err(PRE_RSYNC "%s", cur);
		} else {
			pr_val_info(PRE_RSYNC "%s", cur);
		}
		cur = tmp + 1;
	}
	free(cpy);
#undef PRE_RSYNC
}

static int
read_pipe(int fd_pipe[2][2], int type, bool log_operation)
{
	char buffer[4096];
	ssize_t count;

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

		log_buffer(buffer, count, type, log_operation);
	}
	close(fd_pipe[type][0]); /* Close read end */
	return 0;
}

/*
 * Read the piped output from the child, assures that all pipes are closed on
 * success and on error.
 */
static int
read_pipes(int fds[2][2], bool log_operation)
{
	int error;

	/* Won't be needed (sterr/stdout write ends) */
	close(fds[0][1]);
	close(fds[1][1]);

	/* stderr pipe */
	error = read_pipe(fds, 0, log_operation);
	if (error) {
		/* Close the other pipe pending to read */
		close(fds[1][0]);
		return error;
	}

	/* stdout pipe, always logs to info */
	return read_pipe(fds, 1, true);
}

/*
 * Downloads the @uri->global file into the @uri->local path.
 */
static int
do_rsync(struct rpki_uri *uri, bool is_ta, bool log_operation)
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
	error = prepare_rsync(uri, is_ta, &args, &args_len);
	if (error)
		return error;

	pr_val_debug("Executing RSYNC:");
	for (i = 0; i < args_len + 1; i++)
		pr_val_debug("    %s", args[i]);

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
		error = read_pipes(fork_fds, log_operation);
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
			pr_val_debug("Child terminated with error code %d.", error);
			if (error == ENOMEM)
				pr_enomem();

			if (!error)
				goto release_args;

			if (retries == config_get_rsync_retry_count()) {
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

/*
 * Returned values if the ancestor URI of @error_uri:
 * 0 - didn't had a previous request error
 * EEXIST - had a previous request error
 * < 0 - nothing, just something bad happened
 */
static int
ancestor_error(char const *error_uri, void *arg)
{
	struct rpki_uri *search = arg;
	struct rpki_uri *req_err_uri;
	int error;

	req_err_uri = NULL;
	error = uri_create_mixed_str(&req_err_uri, error_uri,
	    strlen(error_uri));
	switch(error) {
	case 0:
		break;
	default:
		return ENSURE_NEGATIVE(error);
	}

	/* Ignore non rsync error'd URIs */
	if (!uri_is_rsync(req_err_uri)) {
		uri_refput(req_err_uri);
		return 0;
	}

	error = is_descendant(req_err_uri, search) ? EEXIST : 0;

	uri_refput(req_err_uri);
	return error;
}

/* Validate if the ancestor URI error'd */
static int
check_ancestor_error(struct rpki_uri *requested_uri)
{
	int error;

	error = reqs_errors_foreach(ancestor_error, requested_uri);
	if (error < 0)
		return error;
	/* Return the requests error'd code */
	if (error == EEXIST)
		return EREQFAILED;

	return 0;
}

/**
 * @is_ta: Are we rsync'ing the TA?
 * The TA rsync will not be recursive, and will force SYNC_STRICT
 * (unless the strategy has been set to SYNC_OFF.)
 * Why? Because we should probably not trust the repository until we've
 * validated the TA's public key.
 */
int
download_files(struct rpki_uri *requested_uri, bool is_ta, bool force)
{
	/**
	 * Note:
	 * @requested_uri is the URI we were asked to RSYNC.
	 * @rsync_uri is the URL we're actually going to RSYNC.
	 * (They can differ, depending on config_get_rsync_strategy().)
	 */
	struct validation *state;
	struct uri_list *visited_uris;
	struct rpki_uri *rsync_uri;
	bool to_op_log;
	int error;

	if (!config_get_rsync_enabled())
		return 0;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;

	visited_uris = validation_rsync_visited_uris(state);

	if (!force && is_already_downloaded(requested_uri, visited_uris)) {
		pr_val_debug("No need to redownload '%s'.",
		    uri_val_get_printable(requested_uri));
		return check_ancestor_error(requested_uri);
	}

	if (!force)
		error = get_rsync_uri(requested_uri, is_ta, &rsync_uri);
	else {
		error = check_ancestor_error(requested_uri);
		if (error)
			return error;
		error = handle_strict_strategy(requested_uri, &rsync_uri);
	}

	if (error)
		return error;

	pr_val_debug("Going to RSYNC '%s'.", uri_val_get_printable(rsync_uri));

	to_op_log = reqs_errors_log_uri(uri_get_global(rsync_uri));
	error = do_rsync(rsync_uri, is_ta, to_op_log);
	switch(error) {
	case 0:
		/* Don't store when "force" and if its already downloaded */
		if (!(force && is_already_downloaded(rsync_uri, visited_uris)))
			error = mark_as_downloaded(rsync_uri, visited_uris);
		reqs_errors_rem_uri(uri_get_global(rsync_uri));
		break;
	case EREQFAILED:
		/* All attempts failed, avoid future requests */
		error = reqs_errors_add_uri(uri_get_global(rsync_uri));
		if (error)
			break;
		error = mark_as_downloaded(rsync_uri, visited_uris);
		/* Everything went ok? Return the original error */
		if (!error)
			error = EREQFAILED;
		break;
	default:
		break;
	}

	uri_refput(rsync_uri);
	return error;
}

void
reset_downloaded(void)
{
	struct validation *state;
	struct uri_list *list;
	struct uri *uri;

	state = state_retrieve();
	if (state == NULL)
		return;

	list = validation_rsync_visited_uris(state);

	while (!SLIST_EMPTY(list)) {
		uri = SLIST_FIRST(list);
		SLIST_REMOVE_HEAD(list, next);
		uri_refput(uri->uri);
		free(uri);
	}
}
