#include "rsync.h"

#include <sys/queue.h>
#include <sys/stat.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../common.h"

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
	if (!is_rsync_active) {
		execute_rsync = is_rsync_active;
		return 0;
	}

	rsync_uris = malloc(sizeof(struct uri_list));
	if (!rsync_uris)
		return -ENOMEM;

	SLIST_INIT(rsync_uris);
	return 0;
}

void
rsync_destroy()
{
	struct uri *uri;

	// TODO remove the next 2 lines
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
	char const *rsync_command = "rsync --recursive --delete --times --contimeout=20 "; /* space char at end*/

	error = get_dest_path(rsync_uri, &dest);
	if (error)
		return error;

	command = malloc(strlen(rsync_command) + 1 + strlen(rsync_uri) + 1 + strlen(dest) + 1);
	if (command == NULL)
		return -ENOMEM;

	strcpy(command, rsync_command);
	strcat(command, rsync_uri);
	strcat(command, " ");
	strcat(command, dest);

	free(dest);

	printf("(%s) command = %s \n", __func__, command);

	error = system(command);
	if (error) {
		printf("result rsync %d\n", error);
		perror("rsync");
	}
	free(command);

	return error;
}

static int
get_dest_path(char const *rsync_uri, char **result)
{
	char *local_uri, *temp_str;
	unsigned int result_size;
	int error;

	error = uri_g2l(rsync_uri, strlen(rsync_uri), &local_uri);
	if (error)
		return error;

	if (!is_file(local_uri)) {
		*result = local_uri;
		return 0;
	}

	temp_str = strrchr(local_uri, '/');
	if (temp_str == NULL) {
		// TODO warning msg
		return -EINVAL;
	}
	result_size = temp_str - local_uri + 1; /* add slash (+1) */

	temp_str = malloc(result_size + 1); /* null char (+1) */
	if (temp_str == NULL) {
		return -ENOMEM;
	}
	temp_str[result_size] = '\0'; /*Set null char*/
	strncpy(temp_str, local_uri, result_size);
	free(local_uri);

	*result = temp_str;
	return 0;
}

//static int
//do_rsync(char *rsync_uri)
//{
//	int temp, result;
//
//	char *temp_char;
//	char *rsync_command[] = {"rsync", "--recursive", "--delete", "--times", NULL, NULL, NULL};
//	char *src = "rsync://rpki.afrinic.net/repository/AfriNIC.cer";
//	char *dest = "/home/dhf/Desktop/rpkitest/rpki.afrinic.net/repository/";
//
//	rsync_command[4] = src;
//	rsync_command[5] = dest;
//	temp = 0;
//	while (temp < 7) {
//		temp_char = rsync_command[temp];
//		printf("[%d] ", temp);
//		if (temp_char == NULL) {
//			printf("NULL\n");
//		} else {
//			printf("%s\n", temp_char);
//		}
//		temp++;
//	}
//	printf("pre execv \n");
////	result = execve(rsync_command[0], rsync_command, NULL);
//
//	result = system("rsync --recursive --delete --times rsync://rpki.afrinic.net/repository/AfriNIC.cer /home/dhf/Desktop/rpkitest/rpki.afrinic.net/repository/");
////	printf("result execv %d\n", result);
//	printf("result rsync %d\n", result);
//	perror("rsync");
//	return 0;
//}

static bool
rsync_uri_prefix_equals(struct uri *rsync_uri, char const *new_uri)
{
	size_t uri_len;
	uri_len = strlen(new_uri);

	if (rsync_uri->len > uri_len)
		return false;

	return !strncasecmp(rsync_uri->string, new_uri, rsync_uri->len);
}

static bool
is_uri_in_list(char const *rsync_uri)
{
	struct uri *cursor;
	bool found;

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
	if (rsync_uri == NULL) {
		warnx("Out of memory");
		return -ENOMEM;
	}
	urilen = strlen(rsync_uri_path);

	rsync_uri->string = malloc(urilen + 1);
	if (!rsync_uri->string) {
		free(rsync_uri);
		warnx("Out of memory");
		return -ENOMEM;
	}

	strcpy(rsync_uri->string, rsync_uri_path);
	rsync_uri->len = urilen;
	SLIST_INSERT_HEAD(rsync_uris, rsync_uri, next);

	return 0;
}

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
//		pr_err("Global URI %s does not begin with '%s'.", rsync_uri,
//		    PREFIX);
		return -EINVAL;
	}

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

	// TODO remove the next 2 lines
	if (!execute_rsync)
		return 0;

	if (is_uri_in_list(rsync_uri)){
		printf("(%s) ON LIST: %s\n", __func__, rsync_uri);
		error = 0;
		goto end;
	} else {
		printf("(%s) DOWNLOAD: %s\n",__func__,  rsync_uri);
	}

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
	temp_luri = localuri + repository_len ;

	strcpy(path, repository);
	offset = repository_len;


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

	if (file_has_extension(path, path_len, "cer"))
		return true;
	if (file_has_extension(path, path_len, "gbr"))
		return true;
	if (file_has_extension(path, path_len, "mft"))
		return true;

	return false;
}

static bool
dir_exist(char *path)
{
	int error;
	struct stat _stat;
	error = stat(path, &_stat);
	if (error == -1)
		return false; /* a dir or file not exist*/

	return true;
}

static int
create_dir(char *path)
{
	struct stat _stat;
	int error;
	mode_t mode = 0777;

	if (is_file(path))
		return 0;

	error = stat(path, &_stat);
	if (error != -1) {
		/* a dir or file exist*/
		return 0;
	}

	if (errno != ENOENT) {
		perror("stat");
		return -1; /* another error occurs*/
	}

	error = mkdir(path, mode);
	return error;
}
