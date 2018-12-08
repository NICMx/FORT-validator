#include "tal.h"

#include <sys/queue.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "line_file.h"
#include "log.h"

struct uri {
	char *string;
	SLIST_ENTRY(uri) next;
};

SLIST_HEAD(uri_list, uri);

struct tal {
	struct uri_list uris;
	/* Decoded; not base64. */
	void *spki;
	size_t spki_size;
};

static void
uri_destroy(struct uri *uri)
{
	free(uri->string);
	free(uri);
}

static void
uris_destroy(struct uri_list *uris)
{
	struct uri *uri;

	while (!SLIST_EMPTY(uris)) {
		uri = SLIST_FIRST(uris);
		SLIST_REMOVE_HEAD(uris, next);
		uri_destroy(uri);
	}
}

static int
read_uri(struct line_file *lfile, struct uri **result)
{
	struct uri *uri;
	int err;

	uri = malloc(sizeof(struct uri));
	if (uri == NULL) {
		pr_err("Out of memory.");
		return -ENOMEM;
	}

	err = lfile_read(lfile, &uri->string);
	if (err) {
		/* TODO have lfile_read print error msg */
		free(uri);
		return err;
	}

	*result = uri;
	return 0;
}

static int
read_uris(struct line_file *lfile, struct uri_list *uris)
{
	struct uri *previous, *uri;
	int err;

	err = read_uri(lfile, &uri);
	if (err)
		return err;

	if (strcmp(uri->string, "") == 0) {
		uri_destroy(uri);
		pr_err("TAL file %s contains no URIs", lfile_name(lfile));
		return -EINVAL;
	}

	SLIST_INIT(uris);
	SLIST_INSERT_HEAD(uris, uri, next);

	do {
		previous = uri;

		err = read_uri(lfile, &uri);
		if (err)
			return err;

		if (strcmp(uri->string, "") == 0) {
			uri_destroy(uri);
			return 0; /* Happy path */
		}

		SLIST_INSERT_AFTER(previous, uri, next);
	} while (true);
}

int
tal_load(const char *file_name, struct tal **result)
{
	struct line_file *lfile;
	struct tal *tal;
	int err;

	err = lfile_open(file_name, &lfile);
	if (err)
		return err;

	tal = malloc(sizeof(struct tal));
	if (tal == NULL) {
		lfile_close(lfile);
		return -ENOMEM;
	}

	err = read_uris(lfile, &tal->uris);
	if (err) {
		free(tal);
		lfile_close(lfile);
		return err;
	}

	/* TODO */
	tal->spki = NULL;
	tal->spki_size = 0;

	lfile_close(lfile);
	*result = tal;
	return 0;
}

void tal_destroy(struct tal *tal)
{
	if (tal == NULL)
		return;

	uris_destroy(&tal->uris);
	free(tal->spki);
	free(tal);
}

int
foreach_uri(struct tal *tal, foreach_uri_cb cb)
{
	struct uri *cursor;
	int error;

	SLIST_FOREACH(cursor, &tal->uris, next) {
		error = cb(cursor->string);
		if (error)
			return error;
	}

	return 0;
}
