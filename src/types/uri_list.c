#include "types/uri_list.h"

#include "random.h"
#include "http/http.h"
#include "rrdp/rrdp.h"
#include "rsync/rsync.h"

DEFINE_ARRAY_LIST_FUNCTIONS(uri_list, struct rpki_uri *, static)

void
uris_init(struct uri_list *uris)
{
	uri_list_init(uris);
}

static void
__uri_refput(struct rpki_uri **uri)
{
	uri_refput(*uri);
}

void
uris_cleanup(struct uri_list *uris)
{
	uri_list_cleanup(uris, __uri_refput);
}

int
uris_add(struct uri_list *uris, struct rpki_uri *uri)
{
	return uri_list_add(uris, &uri);
}

/* Steals ownership of @str on success. */
int
uris_add_str(struct uri_list *uris, char *str, enum rpki_uri_type type)
{
	struct rpki_uri *addend;
	int error;

	error = uri_create(str, type, &addend);
	if (error)
		return error;

	return uris_add(uris, addend);
}

bool
uris_contains(struct uri_list *list, struct rpki_uri *uri)
{
	char const *guri;
	struct rpki_uri **node;
	size_t n;

	guri = uri_get_global(uri);

	ARRAYLIST_FOREACH(list, node, n)
		if (strcmp(guri, uri_get_global(*node)) == 0)
			return true;

	return false;
}

static bool
starts_with(char const *global, char const *prefix)
{
	size_t global_len;
	size_t prefix_len;

	global_len = strlen(global);
	prefix_len = strlen(prefix);

	return (global_len < prefix_len)
	    ? false
	    : (strncmp(global, prefix, prefix_len) == 0);
}

static bool
is_http(char const *global)
{
	return starts_with(global, "https://") ||
	       starts_with(global, "http://");
}

static bool
is_rsync(char const *global)
{
	return starts_with(global, "rsync://");
}

static int
http_update(struct rpki_uri *uri)
{
	return http_get(uri, file_get_modification_time(uri_get_local(uri)));
}

static struct rpki_uri *
try_download(struct uri_list *uris, bool try_rrdp, bool try_rsync)
{
	struct rpki_uri **__uri;
	struct rpki_uri *uri;
	char const *guri;
	size_t u;

	ARRAYLIST_FOREACH(uris, __uri, u) {
		uri = *__uri;
		guri = uri_get_global(uri);

		if (try_rrdp && is_http(guri)) {
			if (uri_get_type(uri) == URI_TYPE_VERSATILE) {
				if (http_update(uri) == 0)
					return uri;
			} else {
				if (rrdp_update(uri) == 0)
					return uri;
			}
		}
		if (try_rsync && is_rsync(guri)) {
			if (rsync_download_files(uri, false) == 0)
				return 0;
		}
	}

	return NULL;
}

/*
 * Updates the local/cached/cloned version of the content pointed by @uris.
 * Will download the files, unless it realizes the cache is already up-to-date.
 * Stops on (and returns) the first success.
 *
 * Assumes the parent certificate has already been added to the trusted stack.
 */
struct rpki_uri *
uris_download(struct uri_list *uris)
{
	struct rpki_uri *result;

	if (config_get_http_priority() > config_get_rsync_priority()) {
		result = try_download(uris, true, false);
		if (result != NULL)
			return result;
		pr_val_debug("RRDP didn't work. Trying rsync...");
		result = try_download(uris, false, true);

	} else if (config_get_http_priority() < config_get_rsync_priority()) {
		result = try_download(uris, false, true);
		if (result != NULL)
			return result;
		pr_val_debug("rsync didn't work. Trying RRDP...");
		result = try_download(uris, true, false);

	} else {
		result = try_download(uris, true, true);
	}

	if (result == NULL)
		pr_val_err("None of the URLs yielded a successful download.");
	return result;
}
