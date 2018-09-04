#include "tal.h"

#include <sys/queue.h>
#include <sys/stat.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <glib/gi18n.h>

#include <stdio.h>

#include "common.h"
#include "line_file.h"

struct uri {
	char *string;
	SLIST_ENTRY(uri) next;
};

SLIST_HEAD(uri_list, uri);

struct tal {
	struct uri_list uris;
	/* Decoded; not base64. */
	guchar *spki;
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
		warnx("Out of memory");
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
		warnx("TAL file %s contains no URIs", lfile_name(lfile));
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

/*
 * Will usually allocate slightly more because of the newlines, but I'm fine
 * with it.
 */
static size_t
get_spki_alloc_size(struct line_file *lfile)
{
	struct stat st;
	size_t result;

	stat(lfile_name(lfile), &st);
	result = st.st_size - lfile_offset(lfile);

	/*
	 * See the documentation for g_base64_decode_step().
	 * I added `+ 1`. It's because `result / 4` truncates, and I'm not sure
	 * if the original equation meant to round up.
	 */
	return (result / 4 + 1) * 3 + 3;
}

static int
read_spki(struct line_file *lfile, struct tal *tal)
{
	char *line;
	gint state = 0;
	guint save = 0;
	int err;

	tal->spki = malloc(get_spki_alloc_size(lfile));
	if (tal->spki == NULL)
		return -ENOMEM;
	tal->spki_size = 0;

	do {
		err = lfile_read(lfile, &line);
		if (err) {
			free(tal->spki);
			return err;
		}

		if (line == NULL)
			return 0;

		tal->spki_size += g_base64_decode_step(line, strlen(line),
		    tal->spki + tal->spki_size, &state, &save);
		free(line);
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

	err = read_spki(lfile, tal);
	if (err) {
		uris_destroy(&tal->uris);
		free(tal);
		lfile_close(lfile);
		return err;
	}

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
