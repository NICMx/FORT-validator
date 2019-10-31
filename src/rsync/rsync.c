#include "rsync.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h> /* SIGINT, SIGQUIT, etc */
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/wait.h>

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

	if (config_get_sync_strategy() == SYNC_STRICT)
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
				return uri_create_str(dst, global, i);
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
	switch (config_get_sync_strategy()) {
	case SYNC_ROOT:
		return handle_root_strategy(requested_uri, rsync_uri);
	case SYNC_ROOT_EXCEPT_TA:
		return is_ta
		    ? handle_strict_strategy(requested_uri, rsync_uri)
		    : handle_root_strategy(requested_uri, rsync_uri);
	case SYNC_STRICT:
		return handle_strict_strategy(requested_uri, rsync_uri);
	case SYNC_OFF:
		break;
	}

	pr_crit("Invalid sync strategy: %u", config_get_sync_strategy());
}

static int
dir_exists(char const *path, bool *result)
{
	struct stat _stat;
	char *last_slash;

	last_slash = strrchr(path, '/');
	if (last_slash == NULL) {
		/*
		 * Simply because create_dir_recursive() has nothing meaningful
		 * to do when this happens. It's a pretty strange error.
		 */
		*result = true;
		return 0;
	}

	*last_slash = '\0';

	if (stat(path, &_stat) == 0) {
		if (!S_ISDIR(_stat.st_mode)) {
			return pr_err("Path '%s' exists and is not a directory.",
			    path);
		}
		*result = true;
	} else if (errno == ENOENT) {
		*result = false;
	} else {
		return pr_errno(errno, "stat() failed");
	}

	*last_slash = '/';
	return 0;
}

static int
create_dir(char *path)
{
	int error;

	error = mkdir(path, 0777);

	if (error && errno != EEXIST)
		return pr_errno(errno, "Error while making directory '%s'",
		    path);

	return 0;
}

/**
 * Apparently, RSYNC does not like to create parent directories.
 * This function fixes that.
 */
static int
create_dir_recursive(struct rpki_uri *uri)
{
	char *localuri;
	int i, error;
	bool exist = false;

	error = dir_exists(uri_get_local(uri), &exist);
	if (error)
		return error;
	if (exist)
		return 0;

	localuri = strdup(uri_get_local(uri));
	if (localuri == NULL)
		return pr_enomem();

	for (i = 1; localuri[i] != '\0'; i++) {
		if (localuri[i] == '/') {
			localuri[i] = '\0';
			error = create_dir(localuri);
			localuri[i] = '/';
			if (error) {
				/* error msg already printed */
				free(localuri);
				return error;
			}
		}
	}

	free(localuri);
	return 0;
}

static void
handle_child_thread(struct rpki_uri *uri, bool is_ta)
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

	execvp(copy_args[0], copy_args);
	error = errno;
	pr_err("Could not execute the rsync command: %s",
	    strerror(error));

	/* https://stackoverflow.com/a/14493459/1735458 */
	exit(error);
}

/*
 * Downloads the @uri->global file into the @uri->local path.
 */
static int
do_rsync(struct rpki_uri *uri, bool is_ta)
{
	pid_t child_pid;
	int child_status;
	int error;

	child_status = 0;
	error = create_dir_recursive(uri);
	if (error)
		return error;

	/* We need to fork because execvp() magics the thread away. */
	child_pid = fork();
	if (child_pid == 0) {
		/* This code is run by the child. */
		handle_child_thread(uri, is_ta);
	}

	/* This code is run by us. */

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
		return error;
	}

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
			pr_err("The RSYNC was terminated by a signal I don't have a handler for. Dunno; guess I'll just die.");
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
	 * (They can differ, depending on config_get_sync_strategy().)
	 */
	struct validation *state;
	struct uri_list *visited_uris;
	struct rpki_uri *rsync_uri;
	int error;

	if (config_get_sync_strategy() == SYNC_OFF)
		return 0;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;

	visited_uris = validation_visited_uris(state);

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
