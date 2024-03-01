#ifndef SRC_TYPES_URI_H_
#define SRC_TYPES_URI_H_

#include "asn1/asn1c/IA5String.h"
#include "data_structure/array_list.h"

enum uri_type {
	UT_TA_RSYNC, /* TAL's TA URL; downloaded via rsync. */
	UT_TA_HTTP, /* TAL's TA URL; downloaded via HTTP. */
	UT_RPP, /* caRepository; downloaded via rsync. */
	UT_NOTIF, /* rpkiNotify; downloaded via HTTP. */
	UT_TMP, /* Snapshot or delta; Downloaded via HTTP. */
	UT_CAGED, /* Endangered species. */

	UT_AIA, /* caIssuers. Not downloaded. */
	UT_SO, /* signedObject. Not downloaded. */
	UT_MFT, /* rpkiManifest. Not downloaded. */
};

struct rpki_uri;

int __uri_create(struct rpki_uri **, char const *, enum uri_type,
    struct rpki_uri *, void const *, size_t);
int uri_create_mft(struct rpki_uri **, char const *, struct rpki_uri *,
    struct rpki_uri *, IA5String_t *);
struct rpki_uri *uri_create_cache(char const *);

#define uri_create(uri, tal, type, notif, guri) \
	__uri_create(uri, tal, type, notif, guri, strlen(guri))
#define uri_create_caged(uri, tal, notif, guri, guri_len) \
	__uri_create(uri, tal, UT_CAGED, notif, guri, guri_len)
#define uri_create_cage(uri, tal, notif) \
	uri_create_caged(uri, tal, notif, "", 0)

struct rpki_uri *uri_refget(struct rpki_uri *);
void uri_refput(struct rpki_uri *);

/*
 * Note that, if you intend to print some URI, you're likely supposed to use
 * uri_get_printable() instead.
 */
char const *uri_get_global(struct rpki_uri *);
char const *uri_get_local(struct rpki_uri *);
size_t uri_get_global_len(struct rpki_uri *);

bool uri_equals(struct rpki_uri *, struct rpki_uri *);
bool uri_has_extension(struct rpki_uri *, char const *);
bool uri_is_certificate(struct rpki_uri *);

enum uri_type uri_get_type(struct rpki_uri *);

char const *uri_val_get_printable(struct rpki_uri *);
char const *uri_op_get_printable(struct rpki_uri *);

char *uri_get_rrdp_workspace(char const *, struct rpki_uri *);

/* Plural */

DEFINE_ARRAY_LIST_STRUCT(uri_list, struct rpki_uri *);

void uris_init(struct uri_list *);
void uris_cleanup(struct uri_list *);

void uris_add(struct uri_list *, struct rpki_uri *);

#endif /* SRC_TYPES_URI_H_ */
