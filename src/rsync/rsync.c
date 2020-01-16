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
#include "str.h"
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
handle_child_thread(struct rpki_uri *uri, bool is_ta, int fds[2][2])
{
	/* THIS FUNCTION MUST NEVER RETURN!!! */

	struct string_array const *config_args;
	char **copy_args;
	unsigned int i;
	int error;

	config_args = config_get_rsync_args(is_ta);
	/*
	 * We need to work on a copy, because the config args are immutable,
	 * and we need to add the program name (for some reason) and NULL
	 * elements, and replace $REMOTE and $LOCAL.
	 */
	copy_args = calloc(config_args->length + 2, sizeof(char *));
	if (copy_args == NULL)
		exit(pr_enomem());

	copy_args[0] = config_get_rsync_program();
	copy_args[config_args->length + 1] = NULL;

	memcpy(copy_args + 1, config_args->array,
	    config_args->length * sizeof(char *));

	for (i = 1; i < config_args->length + 1; i++) {
		if (strcmp(copy_args[i], "$REMOTE") == 0)
			copy_args[i] = strdup(uri_get_global(uri));
		else if (strcmp(copy_args[i], "$LOCAL") == 0)
			copy_args[i] = strdup(uri_get_local(uri));
		if (copy_args[i] == NULL)
			exit(pr_enomem());
	}

	pr_debug("Executing RSYNC:");
	for (i = 0; i < config_args->length + 1; i++)
		pr_debug("    %s", copy_args[i]);

	duplicate_fds(fds);

	execvp(copy_args[0], copy_args);
	error = errno;
	pr_err("Could not execute the rsync command: %s",
	    strerror(error));

	/* https://stackoverflow.com/a/14493459/1735458 */
	exit(error);
}

static int
create_pipes(int fds[2][2])
{
	if (pipe(fds[0]) == -1)
		return -pr_errno(errno, "Piping rsync stderr");
	if (pipe(fds[1]) == -1)
		return -pr_errno(errno, "Piping rsync stdout");
	return 0;
}

static void
log_buffer(char const *buffer, ssize_t read, int type)
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
		if (type == 0)
			pr_err(PRE_RSYNC "%s", cur);
		else
			pr_info(PRE_RSYNC "%s", cur);
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

	while (1) {
		count = read(fd_pipe[type][0], buffer, sizeof(buffer));
		if (count == -1) {
			if (errno == EINTR)
				continue;
			return -pr_errno(errno, "Reading rsync buffer");
		}
		if (count == 0)
			break;

		log_buffer(buffer, count, type);
	}
	close(fd_pipe[type][0]);
	return 0;
}

static int
read_pipes(int fds[2][2])
{
	int error;

	/* Won't be needed */
	close(fds[0][1]);
	close(fds[1][1]);

	/* stderr pipe */
	error = read_pipe(fds, 0);
	if (error)
		return error;

	/* stdout pipe */
	return read_pipe(fds, 1);
}

/*
 * Downloads the @uri->global file into the @uri->local path.
 */
static int
do_rsync(struct rpki_uri *uri, bool is_ta)
{
	/* Descriptors to pipe stderr (first element) and stdout (second) */
	int fork_fds[2][2];
	pid_t child_pid;
	unsigned int retries;
	int child_status;
	int error;

	retries = 0;
	do {
		child_status = 0;
		error = create_dir_recursive(uri_get_local(uri));
		if (error)
			return error;

		error = create_pipes(fork_fds);
		if (error)
			return error;

		/* We need to fork because execvp() magics the thread away. */
		child_pid = fork();
		if (child_pid == 0) {
			/* This code is run by the child. */
			handle_child_thread(uri, is_ta, fork_fds);
		}

		/* This code is run by us. */
		error = read_pipes(fork_fds);
		if (error)
			return error;

		error = waitpid(child_pid, &child_status, 0);
		do {
			if (error == -1) {
				error = errno;
				pr_err("The rsync sub-process returned error %d (%s)",
				    error, strerror(error));
				if (child_status > 0)
					break;
				return error;
			}
		} while (0);

		if (WIFEXITED(child_status)) {
			/* Happy path (but also sad path sometimes). */
			error = WEXITSTATUS(child_status);
			pr_debug("Child terminated with error code %d.", error);
			if (!error)
				return 0;
			if (retries == config_get_rsync_retry_count()) {
				pr_info("Max RSYNC retries (%u) reached on '%s', won't retry again.",
				    retries, uri_get_global(uri));
				return error;
			}
			pr_info("Retrying RSYNC '%s' in %u seconds, %u attempts remaining.",
			    uri_get_global(uri),
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
			pr_err("RSYNC was user-interrupted. Guess I'll interrupt myself too.");
			break;
		case SIGQUIT:
			pr_err("RSYNC received a quit signal. Guess I'll quit as well.");
			break;
		case SIGKILL:
			pr_err("Killed.");
			break;
		default:
			pr_err("The RSYNC was terminated by a signal [%d] I don't have a handler for. Dunno; guess I'll just die.",
			    WTERMSIG(child_status));
			break;
		}
		return -EINTR; /* Meh? */
	}

	pr_err("The RSYNC command died in a way I don't have a handler for. Dunno; guess I'll die as well.");
	return -EINVAL;
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
	int error;

	if (!config_get_rsync_enabled())
		return 0;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;

	visited_uris = validation_rsync_visited_uris(state);

	if (!force && is_already_downloaded(requested_uri, visited_uris)) {
		pr_debug("No need to redownload '%s'.",
		    uri_get_printable(requested_uri));
		return 0;
	}

	if (!force)
		error = get_rsync_uri(requested_uri, is_ta, &rsync_uri);
	else
		error = handle_strict_strategy(requested_uri, &rsync_uri);

	if (error)
		return error;

	pr_debug("Going to RSYNC '%s'.", uri_get_printable(rsync_uri));

	/* Don't store when "force" and if its already downloaded */
	error = do_rsync(rsync_uri, is_ta);
	if (!error &&
	    !(force && is_already_downloaded(rsync_uri, visited_uris)))
		error = mark_as_downloaded(rsync_uri, visited_uris);

	uri_refput(rsync_uri);
	return error;
}
