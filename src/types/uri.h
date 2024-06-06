#ifndef SRC_TYPES_URI_H_
#define SRC_TYPES_URI_H_

#include "asn1/asn1c/IA5String.h"
#include "data_structure/array_list.h"

/*
 * "Long" time = seven days.
 * Currently hardcoded, but queued for tweakability.
 */
enum uri_type {
	/*
	 * TAL's TA URL.
	 * The file is cached until it's untraversed for a "long" time.
	 */
	UT_TA_RSYNC,
	UT_TA_HTTP,

	/*
	 * (rsync) Repository Publication Point. RFC 6481.
	 * The directory is cached until it's untraversed for a "long" time.
	 */
	UT_RPP,

	/*
	 * An RRDP notification file; downloaded via HTTP.
	 * The file itself is not cached, but we preserve a handful of metadata
	 * that is needed in subsequent iterations.
	 * The metadata is cached until it's untraversed for a "long" time.
	 */
	UT_NOTIF,

	/*
	 * RRDP Snapshot or Delta; downloaded via HTTP.
	 * The file itself is not cached, but we preserve some small metadata.
	 * The metadata is destroyed once the iteration finishes.
	 */
	UT_TMP,

	/*
	 * Endangered species; bound to be removed once RFC 9286 is implemented.
	 */
	UT_CAGED,

	UT_AIA, /* caIssuers. Not directly downloaded. */
	UT_SO, /* signedObject. Not directly downloaded. */
	UT_MFT, /* rpkiManifest. Not directly downloaded. */
};

struct rpki_uri;

int uri_create(struct rpki_uri **, enum uri_type, struct rpki_uri *,
	       char const *);
int uri_create_mft(struct rpki_uri **, struct rpki_uri *, struct rpki_uri *,
		   IA5String_t *);
struct rpki_uri *uri_create_cache(char const *);

#define uri_create_caged(uri, notif, guri) \
	uri_create(uri, UT_CAGED, notif, guri)
#define uri_create_cage(uri, notif) \
	uri_create_caged(uri, notif, NULL)

struct rpki_uri *uri_refget(struct rpki_uri *);
void uri_refput(struct rpki_uri *);

/*
 * Note that, if you intend to print some URI, you're likely supposed to use
 * uri_get_printable() instead.
 */
char const *uri_get_global(struct rpki_uri *);
char const *uri_get_local(struct rpki_uri *);

bool uri_equals(struct rpki_uri *, struct rpki_uri *);
bool str_same_origin(char const *, char const *);
bool uri_same_origin(struct rpki_uri *, struct rpki_uri *);
bool uri_has_extension(struct rpki_uri *, char const *);
bool uri_is_certificate(struct rpki_uri *);

enum uri_type uri_get_type(struct rpki_uri *);

char const *uri_val_get_printable(struct rpki_uri *);
char const *uri_op_get_printable(struct rpki_uri *);

char *uri_get_rrdp_workspace(struct rpki_uri *);

/* Plural */

DEFINE_ARRAY_LIST_STRUCT(uri_list, struct rpki_uri *);

void uris_init(struct uri_list *);
void uris_cleanup(struct uri_list *);

void uris_add(struct uri_list *, struct rpki_uri *);

#endif /* SRC_TYPES_URI_H_ */
