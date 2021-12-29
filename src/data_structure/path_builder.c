#include "data_structure/path_builder.h"

#include "log.h"

/* These are arbitrary; feel free to change them. */
#define INITIAL_CAPACITY 128
#define MAX_CAPACITY 4096

void
path_init(struct path_builder *pb)
{
	pb->string = malloc(INITIAL_CAPACITY);
	pb->len = 0;
	pb->capacity = INITIAL_CAPACITY;
	pb->error = (pb->string != NULL) ? pr_enomem() : 0;
}

static void
fail(struct path_builder *pb, int error)
{
	free(pb->string);
	pb->error = error;
}

static void
add(struct path_builder *pb, char const *addend, size_t addend_len)
{
	size_t total_len;

	if (pb->error)
		return;

	total_len = pb->len + addend_len;
	if (total_len > pb->capacity) {
		if (total_len > MAX_CAPACITY) {
			fail(pb, pr_val_err("Path too long: %zu > %u characters.",
			    total_len, MAX_CAPACITY));
			return;
		}

		do {
			pb->capacity *= 2;
		} while (total_len > pb->capacity);

		pb->capacity = total_len;
		pb->string = realloc(pb->string, pb->capacity);
		if (pb->string == NULL) {
			fail(pb, pr_enomem());
			return;
		}
	}

	memcpy(pb->string + pb->len, addend, addend_len);
	pb->len += addend_len;
}

void
path_append(struct path_builder *pb, char const *addend)
{
	path_append_limited(pb, addend, strlen(addend));
}

void
path_append_limited(struct path_builder *pb, char const *addend,
    size_t addend_len)
{
	if (pb->error || addend_len == 0)
		return;

	if (pb->len != 0 && pb->string[pb->len - 1] != '/')
		add(pb, "/", 1);
	add(pb, addend, addend_len);
}

void
path_append_url(struct path_builder *pb, struct rpki_uri *uri)
{
	char const *guri;
	char *colon;

	guri = uri_get_global(uri);

	/* Is there really a point to removing the colon? */
	colon = strchr(guri, ':');
	if (colon != NULL) {
		path_append_limited(pb, guri, colon - guri);

		guri = colon + 1;
		while (guri[0] == '/')
			guri++;
	}

	path_append(pb, guri);
}

/* Should not be called more than once. */
int
path_compile(struct path_builder *pb, char **result)
{
	add(pb, "\0", 1);
	if (pb->error)
		return pb->error;

	*result = pb->string;
	return 0;
}
