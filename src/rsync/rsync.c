#include "rsync.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/cdefs.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "config.h"
#include "log.h"
#include "str.h"

struct uri {
	char *string;
	size_t len;
	SLIST_ENTRY(uri) next;
};

/** URIs that we have already downloaded. */
SLIST_HEAD(uri_list, uri) visited_uris;

/* static char const *const RSYNC_PREFIX = "rsync://"; */

int
rsync_init(void)
{
	SLIST_INIT(&visited_uris);
	return 0;
}

void
rsync_destroy(void)
{
	struct uri *uri;

	while (!SLIST_EMPTY(&visited_uris)) {
		uri = SLIST_FIRST(&visited_uris);
		SLIST_REMOVE_HEAD(&visited_uris, next);
		free(uri->string);
		free(uri);
	}
}

/*
 * Returns true if @ancestor an ancestor of @descendant, or @descendant itself.
 * Returns false otherwise.
 */
static bool
is_descendant(struct uri *ancestor, struct rpki_uri const *descendant)
{
	struct string_tokenizer ancestor_tokenizer;
	struct string_tokenizer descendant_tokenizer;

	string_tokenizer_init(&ancestor_tokenizer, ancestor->string,
	    ancestor->len, '/');
	string_tokenizer_init(&descendant_tokenizer, descendant->global,
	    descendant->global_len, '/');

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
is_already_downloaded(struct rpki_uri const *uri)
{
	struct uri *cursor;

	/* TODO (next iteration) this is begging for a radix trie. */
	SLIST_FOREACH(cursor, &visited_uris, next)
		if (is_descendant(cursor, uri))
			return true;

	return false;
}

static int
mark_as_downloaded(struct rpki_uri *uri)
{
	struct uri *node;

	node = malloc(sizeof(struct uri));
	if (node == NULL)
		return pr_enomem();

	node->string = uri->global;
	node->len = uri->global_len;
	uri->global = NULL; /* Ownership transferred. */

	SLIST_INSERT_HEAD(&visited_uris, node, next);

	return 0;
}

static int
handle_strict_strategy(struct rpki_uri const *requested_uri,
    struct rpki_uri *rsync_uri)
{
	return uri_clone(requested_uri, rsync_uri);
}

static int
handle_root_strategy(struct rpki_uri const *src, struct rpki_uri *dst)
{
	unsigned int slashes;
	size_t i;

	slashes = 0;
	for (i = 0; i < src->global_len; i++) {
		if (src->global[i] == '/') {
			slashes++;
			if (slashes == 4)
				return uri_init_str(dst, src->global, i);
		}
	}

	return uri_clone(src, dst);
}

static int
get_rsync_uri(struct rpki_uri const *requested_uri, struct rpki_uri *rsync_uri)
{
	switch (config_get_sync_strategy()) {
	case SYNC_ROOT:
		return handle_root_strategy(requested_uri, rsync_uri);
	case SYNC_STRICT:
		return handle_strict_strategy(requested_uri, rsync_uri);
	case SYNC_OFF:
		return pr_crit("Supposedly unreachable code reached.");
	}

	return pr_crit("Unknown sync strategy: %u", config_get_sync_strategy());
}

static int
dir_exists(char *path, bool *result)
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

	switch (stat(path, &_stat)) {
	case 0:
		if (!S_ISDIR(_stat.st_mode)) {
			return pr_err("Path '%s' exists and is not a directory.",
			    path);
		}

		*result = true;
		break;
	case ENOENT:
		*result = false;
		break;
	default:
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
create_dir_recursive(char *localuri)
{
	size_t repository_len;
	int i, error;
	bool exist = false;

	error = dir_exists(localuri, &exist);
	if (error)
		return error;

	if (exist)
		return 0;

	repository_len = strlen(config_get_local_repository());
	for (i = 1 + repository_len; localuri[i] != '\0'; i++) {
		if (localuri[i] == '/') {
			localuri[i] = '\0';
			error = create_dir(localuri);
			localuri[i] = '/';
			if (error) {
				/* error msg already printed */
				return error;
			}
		}
	}

	return 0;
}

static void
handle_child_thread(struct rpki_uri *uri)
{
	/* THIS FUNCTION MUST NEVER RETURN!!! */

	struct string_array const *config_args;
	char **copy_args;
	unsigned int i;
	int error;

	config_args = config_get_rsync_args();
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
			copy_args[i] = uri->global;
		else if (strcmp(copy_args[i], "$LOCAL") == 0)
			copy_args[i] = uri->local;
	}

	pr_debug("Executing RSYNC:");
	for (i = 0; i < config_args->length + 1; i++)
		pr_debug("    %s", copy_args[i]);

	execvp(copy_args[0], copy_args);
	error = errno;
	pr_err("Could not execute the rsync command: %s",
	    strerror(error));

	/*
	 * https://stackoverflow.com/a/14493459/1735458
	 * Might as well. Prrbrrrlllt.
	 */
	free(copy_args);

	exit(error);
}

/*
 * Downloads the @uri->global file into the @uri->local path.
 */
static int
do_rsync(struct rpki_uri *uri)
{
	pid_t child_pid;
	int child_status;
	int error;

	error = create_dir_recursive(uri->local);
	if (error)
		return error;

	/* We need to fork because execvp() magics the thread away. */
	child_pid = fork();
	if (child_pid == 0)
		handle_child_thread(uri); /* This code is run by the child. */

	/* This code is run by us. */

	error = waitpid(child_pid, &child_status, 0);
	if (error == -1) {
		error = errno;
		pr_err("The rsync sub-process returned error %d (%s)",
		    error, strerror(error));
		return error;
	}

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
		exit(-EINTR); /* Meh? */
	}

	pr_err("The RSYNC command died in a way I don't have a handler for. Dunno; guess I'll die as well.");
	exit(-EINVAL);
}

int
download_files(struct rpki_uri const *requested_uri)
{
	/**
	 * Note:
	 * @requested_uri is the URI we were asked to RSYNC.
	 * @rsync_uri is the URL we're actually going to RSYNC.
	 * (They can differ, depending on config_get_sync_strategy().)
	 */
	struct rpki_uri rsync_uri;
	int error;

	if (config_get_sync_strategy() == SYNC_OFF)
		return 0;

	if (is_already_downloaded(requested_uri)) {
		pr_debug("No need to redownload '%s'.", requested_uri->global);
		return 0;
	}

	error = get_rsync_uri(requested_uri, &rsync_uri);
	if (error)
		return error;

	pr_debug("Going to RSYNC '%s' ('%s').", rsync_uri.global,
	    rsync_uri.local);

	error = do_rsync(&rsync_uri);
	if (!error)
		error = mark_as_downloaded(&rsync_uri);

	uri_cleanup(&rsync_uri);
	return error;
}
