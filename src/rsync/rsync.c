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
#include "log.h"

struct uri {
	char *string;
	size_t len;
	SLIST_ENTRY(uri) next;
};

SLIST_HEAD(uri_list, uri);

static struct uri_list *rsync_uris;
static bool execute_rsync = true;

//static const char *rsync_command[] = {"rsync", "--recursive", "--delete", "--times", NULL};

static int create_dir_recursive(char *);
static int create_dir(char *);
static int do_rsync(char const *);
static int get_dest_path(char const *, char **);
static bool is_file(char const *);
static bool dir_exist(char *);

int
rsync_init(bool is_rsync_active)
{
	// TODO remove the next 2 lines
	/*
	 * TODO (rsync) No, don't. Disabling rsync will forever be a useful
	 * debugging feature.
	 */
	if (!is_rsync_active) {
		execute_rsync = is_rsync_active;
		return 0;
	}

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

	if (!execute_rsync)
		return;

	while (!SLIST_EMPTY(rsync_uris)) {
		uri = SLIST_FIRST(rsync_uris);
		SLIST_REMOVE_HEAD(rsync_uris, next);
		free(uri->string);
		free(uri);
	}

	free(rsync_uris);
}

static int
do_rsync(char const *rsync_uri)
{
	int error;
	char *command;
	char *dest;
	/* TODO (rsync) comment is invisible in narrow editors */
	char const *rsync_command = "rsync --recursive --delete --times --contimeout=20 "; /* space char at end*/

	/* TODO (rsync) dest is leaking */
	error = get_dest_path(rsync_uri, &dest);
	if (error)
		return error;

	/* TODO (rsync) It seems that rsync_command does not need a `+ 1` */
	/* TODO (rsync) line exceeds 80 column limit */
	command = malloc(strlen(rsync_command) + 1 + strlen(rsync_uri) + 1 + strlen(dest) + 1);
	if (command == NULL)
		return -ENOMEM;

	strcpy(command, rsync_command);
	strcat(command, rsync_uri);
	strcat(command, " ");
	strcat(command, dest);

	free(dest);

	pr_debug("(%s) command = %s", __func__, command);

	error = system(command);
	if (error) {
		int error2 = errno;
		/*
		 * The error message needs to be really generic because it seems
		 * that the Linux system() and the OpenBSD system() return
		 * different things.
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
 * If @rsync_uri is a certificate, ghostbuster or manifest file, this returns
 * its local location's parent.
 * If @rsync_uri is anything else (including other file types), returns
 * @rsync_uri's local location.
 *
 * TODO (rsync) Why are you doing this? is rsync incapable of synchronizing
 * individual files?
 * TODO (rsync) Also: That's wrong anyway. certificates, ghostbusters and
 * manifests are not the only files RPKI has to handle. There's nothing in the
 * RFCs requiring that only known file types be present, or even that all files
 * must have extensions.
 * If you REALLY need to tell the difference between files and directories,
 * use stat(2) instead.
 */
static int
get_dest_path(char const *rsync_uri, char **result)
{
	char *local_uri, *temp_str;
	unsigned int result_size;
	int error;

	/* TODO (rsync) local_uri is leaking */
	error = uri_g2l(rsync_uri, strlen(rsync_uri), &local_uri);
	if (error)
		return error;

	if (!is_file(local_uri)) {
		*result = local_uri;
		return 0;
	}

	temp_str = strrchr(local_uri, '/');
	if (temp_str == NULL) {
		return pr_err("URI '%s' has no slash.", local_uri);
	}
	result_size = temp_str - local_uri + 1; /* add slash (+1) */

	temp_str = malloc(result_size + 1); /* null char (+1) */
	if (temp_str == NULL) {
		return pr_enomem();
	}
	temp_str[result_size] = '\0'; /*Set null char*/
	strncpy(temp_str, local_uri, result_size);
	free(local_uri);

	*result = temp_str;
	return 0;
}

/*
 * Returns whether new_uri's prefix is rsync_uri.
 * TODO (rsync) why does this not care about nodes? It will return true if
 * `rsync_uri = proto://a/b/c` and `new_uri = proto://a/b/cc`.
 */
static bool
rsync_uri_prefix_equals(struct uri *rsync_uri, char const *new_uri)
{
	size_t uri_len;
	uri_len = strlen(new_uri);

	if (rsync_uri->len > uri_len)
		return false;

	/*
	 * TODO (rsync) Don't use '!' for tests unless it's a boolean.
	 * (OpenBSD style)
	 */
	return !strncasecmp(rsync_uri->string, new_uri, rsync_uri->len);
}

static bool
is_uri_in_list(char const *rsync_uri)
{
	struct uri *cursor;
	bool found;

	/* TODO (rsync) this if doesn't seem to be doing anything */
	if (SLIST_EMPTY(rsync_uris)) {
		return false;
	}

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
add_uri_to_list(char const *rsync_uri_path)
{
	struct uri *rsync_uri;
	size_t urilen;

	rsync_uri = malloc(sizeof(struct uri));
	if (rsync_uri == NULL)
		return pr_enomem();
	urilen = strlen(rsync_uri_path);

	rsync_uri->string = malloc(urilen + 1);
	if (!rsync_uri->string) {
		free(rsync_uri);
		return pr_enomem();
	}

	/*
	 * TODO (rsync) caller frees rsync_uri_path right after calling this.
	 * Transfer ownership instead so you don't need the extra allocate, copy
	 * and free.
	 */
	strcpy(rsync_uri->string, rsync_uri_path);
	rsync_uri->len = urilen;
	SLIST_INSERT_HEAD(rsync_uris, rsync_uri, next);

	return 0;
}

/*
 * Returns rsync_uri, truncated to the second significant slash.
 * I have no idea why.
 *
 * Examples:
 *
 * 	rsync_uri: rsync://aa/bb/cc/dd/ee/ff/gg/hh/ii
 * 	result:    rsync://aa/bb/
 *
 * 	rsync_uri: rsync://aa/bb/
 * 	result:    rsync://aa/bb/
 *
 * 	rsync_uri: rsync://aa/
 * 	result:    rsync://aa//
 *
 * 	rsync_uri: rsync://aa
 * 	result:    rsync://aa
 */
static int
short_uri(char const *rsync_uri, char **result)
{
	char const *const PREFIX = "rsync://";
	char const *tmp;
	char *short_uri;
	size_t result_len;
	size_t prefix_len;

	prefix_len = strlen(PREFIX);

	if (strncmp(PREFIX, rsync_uri, prefix_len) != 0) {
		/* TODO (rsync) why is this commented out? */
//		pr_err("Global URI %s does not begin with '%s'.", rsync_uri,
//		    PREFIX);
		return -EINVAL;
	}

	/*
	 * TODO (rsync) It took me a while to notice that this loop does not
	 * actually iterate. Why did you add it? It's misleading. If it's
	 * because you wanted to break instead of goto in the `tmp == NULL` if,
	 * then this should be a separate function instead.
	 */
	do {
		tmp = rsync_uri + prefix_len;
		tmp = strchr(tmp, '/');

		if (tmp == NULL) {
			result_len = strlen(rsync_uri);
			break;
		}

		tmp = tmp + 1;
		tmp = strchr(tmp, '/');

		if (tmp != NULL)
			result_len = strlen(rsync_uri) - strlen(tmp);
		else
			result_len = strlen(rsync_uri);

	} while (0);

	short_uri = malloc(result_len + 1 + 1); /* slash + null chara */
	if (!short_uri)
		return -ENOMEM;

	strncpy(short_uri, rsync_uri, result_len);
	short_uri[result_len] = '/';
	short_uri[result_len + 1] = '\0';

	*result = short_uri;
	return 0;
}

int
download_files(char const *rsync_uri)
{
	int error;
	char *rsync_uri_path, *localuri;

	if (!execute_rsync)
		return 0;

	if (is_uri_in_list(rsync_uri)){
		pr_debug("(%s) ON LIST: %s", __func__, rsync_uri);
		error = 0;
		goto end;
	} else {
		pr_debug("(%s) DOWNLOAD: %s", __func__, rsync_uri);
	}

	/*
	 * TODO (rsync) I don't understand why you need to do this.
	 * Please comment.
	 */
	error = short_uri(rsync_uri, &rsync_uri_path);
	if (error)
		return error;

	error = uri_g2l(rsync_uri_path, strlen(rsync_uri_path), &localuri);
	if (error)
		goto free_uri_path;

	error = create_dir_recursive(localuri);
	free(localuri);
	if (error)
		goto free_uri_path;

	error = do_rsync(rsync_uri_path);
	if (error)
		goto free_uri_path;

	/*
	 * TODO (rsync) This doesn't look right to me.
	 * The one you queried was rsync_uri. The one you're adding is
	 * rsync_uri_path. It looks like is_uri_in_list() will only match when
	 * short_uri() doesn't do anything.
	 */
	error = add_uri_to_list(rsync_uri_path);

free_uri_path:
	free(rsync_uri_path);
end:
	return error;

}

static int
create_dir_recursive(char *localuri)
{
	char *temp_luri;
	char path[PATH_MAX];
	char *slash;
	size_t localuri_len;
	size_t repository_len;
	unsigned int offset;

	if (dir_exist(localuri))
		return 0;

	localuri_len = strlen(localuri);
	repository_len = strlen(repository);
	temp_luri = localuri + repository_len;

	strcpy(path, repository);
	offset = repository_len;

	/*
	 * TODO (rsync) You might have gone a little overboard with this.
	 * Are you just trying to mkdir -p localuri?
	 * If so, wouldn't this be enough?
	 *
	 * for (i = 1; localuri[i] != '\0'; i++) {
	 * 	if (localuri[i] == '/') {
	 * 		localuri[i] = '\0';
	 * 		create_dir(localuri); // handle error etc etc
	 * 		localuri[i] = '/';
	 * 	}
	 * }
	 *
	 * We're not in Java; our strings are mutable.
	 */

	slash = strchr(temp_luri, '/');
	while (slash != NULL) {
		if (slash == temp_luri) {
			temp_luri++;
			localuri_len--;
			slash = strchr(temp_luri, '/');
			continue;
		}
		strcpy(path + offset, "/");
		offset += 1;
		strncpy(path + offset, temp_luri, slash - temp_luri);
		offset += slash - temp_luri;
		if (offset > localuri_len) {
			break;
		}
		path[offset] = '\0';
		if (create_dir(path) == -1) {
			perror("Error while creating Dir");
			return -1;
		}
		temp_luri += slash - temp_luri + 1;
		slash = strchr(temp_luri, '/');
	}

	if (offset < localuri_len) {
		strcpy(path + offset, "/");
		offset += 1;
		strcpy(path + offset, temp_luri);
		offset = localuri + localuri_len - temp_luri + offset + 1;
		path[offset] = '\0';
	}

	if (create_dir(path) == -1) {
		perror("Error while creating Dir");
		return -1;
	}
	return 0;

}

static bool
is_file(char const *path)
{
	size_t path_len = strlen(path);

	if (file_has_extension(path, path_len, ".cer"))
		return true;
	if (file_has_extension(path, path_len, ".gbr"))
		return true;
	if (file_has_extension(path, path_len, ".mft"))
		return true;

	return false;
}

static bool
dir_exist(char *path)
{
	int error;
	struct stat _stat;
	/*
	 * TODO (rsync) I don't know if you're aware of this, but you can
	 * usually run `man 2 [core c function]` or `man 3 [core c function]`
	 * and get a lot of info.
	 * `man 2 stat`, for example, contains a lot of stuff you clearly need
	 * to read.
	 */
	error = stat(path, &_stat);
	if (error == -1) {
		/*
		 * TODO (rsync) Never do this. stat() can return -1 for a large
		 * number of reasons, and only one of them is "file not found."
		 * Return the error code and send the boolean as an out
		 * parameter.
		 */
		return false; /* a dir or file not exist*/
	}

	/*
	 * TODO (rsync) Don't do this either. The function is called "dir_exist"
	 * but you're returning true even if the node happens to be a file,
	 * a socket, a named pipe, a door, etc etc. What's going to happen if
	 * each of these files interact with calling code?
	 */
	return true;
}

static int
create_dir(char *path)
{
	struct stat _stat;
	int error;
	/*
	 * TODO (rsync) Does this really need to be a variable?
	 * You only use it once.
	 */
	mode_t mode = 0777;

	/*
	 * TODO (rsync) Again. The function is called "create_dir" but you're
	 * returning success on regular file found. And it's really weird that
	 * only .cer, .gbr and .mft files count as directories according to this
	 * if.
	 *
	 * Alternatively: As implemented, this if is redundant because the
	 * return 0 on successful stat below already succeeds on files. Not that
	 * I agree with the stat below either.
	 */
	if (is_file(path))
		return 0;

	error = stat(path, &_stat);
	if (error != -1) {
		/* a dir or file exist*/ /* TODO (rsync) STOP IT. */
		return 0;
	}

	if (errno != ENOENT) {
		/*
		 * TODO (rsync) Error message is unfriendly because the user
		 * has no context on what "stat" is.
		 * Something like "stat() failed" would be a little better.
		 * Use pr_errno() for the automatic errno string. (See `man 3
		 * perror`)
		 */
		perror("stat");
		/*
		 * TODO (rsync) No reason to lose the error code. Return errno
		 * (or better yet: the result of pr_errno(errno)) instead of -1.
		 */
		return -1; /* another error occurs*/
	}

	error = mkdir(path, mode);
	return error; /* TODO (rsync) No message on error */
}
