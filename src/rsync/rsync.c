#include "rsync.h"

#include <sys/queue.h>
#include <sys/stat.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "config.h"
#include "log.h"

struct uri {
	char *string;
	size_t len;
	SLIST_ENTRY(uri) next;
};

SLIST_HEAD(uri_list, uri);

static struct uri_list *rsync_uris;
static char const *const RSYNC_PREFIX = "rsync://";

//static const char *rsync_command[] = {"rsync", "--recursive", "--delete", "--times", NULL};

int
rsync_init(void)
{
	/* Disabling rsync will forever be a useful debugging feature. */
	if (config_get_disable_rsync())
		return 0;

	rsync_uris = malloc(sizeof(struct uri_list));
	if (rsync_uris == NULL)
		return pr_enomem();

	SLIST_INIT(rsync_uris);
	return 0;
}

void
rsync_destroy(void)
{
	struct uri *uri;

	if (config_get_disable_rsync())
		return;

	while (!SLIST_EMPTY(rsync_uris)) {
		uri = SLIST_FIRST(rsync_uris);
		SLIST_REMOVE_HEAD(rsync_uris, next);
		free(uri->string);
		free(uri);
	}

	free(rsync_uris);
}

/*
 * Executes the rsync command. 'rsync_uri' as SRC and 'localuri' as DEST.
 */
static int
do_rsync(char const *rsync_uri, char const *localuri)
{
	int error;
	char *command;
	char const *rsync_command = "rsync --recursive --delete --times "
	    "--contimeout=20 "; /* space char at end*/

	command = malloc(strlen(rsync_command)
	    + strlen(rsync_uri)
	    + 1 /* space char */
	    + strlen(localuri) + 1); /* null char at end*/

	if (command == NULL)
		return pr_enomem();

	strcpy(command, rsync_command);
	strcat(command, rsync_uri);
	strcat(command, " ");
	strcat(command, localuri);

	pr_debug("(%s) command = %s", __func__, command);

	/*
	 * TODO (next iteration) system(3): "Do not use system() from a
	 * privileged program"
	 * I don't think there's a reason to run this program with privileges,
	 * but consider using exec(3) instead.
	 */
	error = system(command);
	if (error) {
		int error2 = errno;
		/*
		 * The error message needs to be really generic because it
		 * seems that the Linux system() and the OpenBSD system()
		 * return different things.
		 */
		pr_err("rsync returned nonzero. result:%d errno:%d",
		    error, error2);
		if (error2)
			pr_errno(error2, "The error message for errno is");
	}
	free(command);

	return error;
}

/*
 * Returns whether new_uri's prefix is rsync_uri.
 */
static bool
rsync_uri_prefix_equals(struct uri *rsync_uri, char const *new_uri)
{
	size_t uri_len;

	uri_len = strlen(new_uri);
	if (rsync_uri->len > uri_len)
		return false;

	if (rsync_uri->string[rsync_uri->len - 1] != '/'
	    && uri_len > rsync_uri->len && new_uri[rsync_uri->len] != '/') {
		return false;
	}

	return strncasecmp(rsync_uri->string, new_uri, rsync_uri->len) == 0;
}

/*
 * Checks if the 'rsync_uri' match equal or as a child of an existing URI in
 * the list.
 */
static bool
is_uri_in_list(char const *rsync_uri)
{
	struct uri *cursor;
	bool found;

	found = false;
	SLIST_FOREACH(cursor, rsync_uris, next) {
		if (rsync_uri_prefix_equals(cursor, rsync_uri)) {
			found = true;
			break;
		}
	}

	return found;
}

static int
add_uri_to_list(char *rsync_uri_path)
{
	struct uri *rsync_uri;

	rsync_uri = malloc(sizeof(struct uri));
	if (rsync_uri == NULL)
		return pr_enomem();

	rsync_uri->string = rsync_uri_path;
	rsync_uri->len = strlen(rsync_uri_path);

	SLIST_INSERT_HEAD(rsync_uris, rsync_uri, next);

	return 0;
}

/*
 * Compares two URIs to obtain the common path if exist.
 * Return NULL if URIs does not match or only match in its domain name.
 * E.g. uri1=proto://a/b/c/d uri2=proto://a/b/c/f, will return proto://a/b/c/
 */
static int
find_prefix_path(char const *uri1, char const *uri2, char **result)
{
	int i, error;
	char const *tmp, *last_equal;

	*result = NULL;
	last_equal = NULL;
	error = 0;

	/*
	 * This code looks for 3 slashes to start compare path section.
	 */
	tmp = uri1;
	for (i = 0; i < 3; i++) {
		tmp = strchr(tmp, '/');
		if (tmp == NULL) {
			goto end;
		}
		tmp++;
	}

	/* Compare protocol and domain. */
	if (strncmp(uri1, uri2, tmp - uri1) != 0)
		goto end;

	while((tmp = strchr(tmp, '/')) != NULL) {
		if (strncmp(uri1, uri2, tmp - uri1) != 0) {
			break;
		}
		last_equal = tmp;
		tmp++;
	}

	if (last_equal != NULL) {
		/*+ 1 slash + 1 null char*/
		*result = malloc(last_equal - uri1
		    + 1  /* + slash char */
		    + 1); /* + null char */
		if (*result == NULL) {
			error = pr_enomem();
			goto end;
		}
		strncpy(*result, uri1, last_equal - uri1 + 1);
		(*result)[last_equal - uri1 + 1] = '\0';
	}

end:
	return error;
}

/*
 * Compares rsync_uri against the uri_list and checks if can obtain a common
 * short path.
 * Returns NULL if URIs does not match any URI in the List.
 * @see find_prefix_path
 */
static int
compare_uris_and_short(char const *rsync_uri, char **result)
{
	struct uri *cursor;
	int error;

	*result = NULL;
	SLIST_FOREACH(cursor, rsync_uris, next) {
		error = find_prefix_path(rsync_uri, cursor->string, result);

		if (error)
			return error;

		if (*result != NULL)
			break;
	}

	return 0;
}

/*
 * Removes filename or last path if not end with an slash char.
 */
static int
get_path_only(char const *uri, size_t uri_len, size_t rsync_prefix_len,
    char **result)
{
	int error, i;
	char tmp_uri[uri_len + 1];
	char *slash_search;
	bool is_domain_only;

	slash_search = NULL;
	is_domain_only = false;
	error = 0;

	for (i = 0; i < uri_len + 1; i++) {
		tmp_uri[i] = uri[i];
	}

	if (tmp_uri[uri_len - 1] != '/') {
		slash_search = strrchr(tmp_uri, '/');
	}

	if (slash_search != NULL) {
		if ((slash_search - tmp_uri) > rsync_prefix_len) {
			tmp_uri[slash_search - tmp_uri + 1] = '\0';
			uri_len = strlen(tmp_uri);
		} else {
			is_domain_only = true;
			slash_search = NULL;
		}
	}

	if (is_domain_only)
		uri_len++; /* Add slash */

	*result = malloc(uri_len + 1); /* +1 null char */
	if (*result == NULL) {
		error = pr_enomem();
		goto end;
	}

	strcpy(*result, tmp_uri);

	if (is_domain_only) {
		(*result)[uri_len - 1] = '/';
		(*result)[uri_len] = '\0';
	}

end:
	return error;
}

static int
dir_exist(char *path, bool *result)
{
	struct stat _stat;
	int error;

	error = stat(path, &_stat);
	if (error != 0) {
		if (errno == ENOENT) {
			*result = false;
			goto end;
		} else {
			return pr_errno(errno, "stat() failed");
		}
	}

	if (!S_ISDIR(_stat.st_mode))
		return pr_err("Path '%s' exist but is not a directory", path);

	*result = true;
end:
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

static int
create_dir_recursive(char *localuri)
{
	size_t repository_len;
	int i, error;
	bool exist = false;

	error = dir_exist(localuri, &exist);
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

int
download_files(struct rpki_uri const *uri)
{
	size_t prefix_len;
	char *rsync_uri_path, *localuri, *tmp;
	int error;

	prefix_len = strlen(RSYNC_PREFIX);

	if (config_get_disable_rsync())
		return 0;

	if (uri->global_len < prefix_len ||
	    strncmp(RSYNC_PREFIX, uri->global, prefix_len) != 0) {
		pr_err("Global URI '%s' does not begin with '%s'.",
		    uri->global, RSYNC_PREFIX);
		return ENOTRSYNC; /* Not really an error, so not negative */
	}

	if (is_uri_in_list(uri->global)){
		pr_debug("(%s) ON LIST: %s", __func__, uri->global);
		error = 0;
		goto end;
	} else {
		pr_debug("(%s) DOWNLOAD: %s", __func__, uri->global);
	}

	error = get_path_only(uri->global, uri->global_len, prefix_len,
	    &rsync_uri_path);
	if (error)
		return error;

	error = compare_uris_and_short(rsync_uri_path, &tmp);
	if (error) {
		goto free_uri_path;
	}

	if (tmp != NULL) {
		free(rsync_uri_path);
		rsync_uri_path = tmp;
	}

	error = uri_g2l(rsync_uri_path, &localuri);
	if (error)
		goto free_uri_path;

	error = create_dir_recursive(localuri);
	if (error)
		goto free_uri_path;

	error = do_rsync(rsync_uri_path, localuri);
	free(localuri);
	if (error)
		goto free_uri_path;

	error = add_uri_to_list(rsync_uri_path);
	if (error)
		goto free_uri_path;

	return 0;

free_uri_path:
	free(rsync_uri_path);
end:
	return error;

}
