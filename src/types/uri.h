#ifndef SRC_TYPES_URI_H_
#define SRC_TYPES_URI_H_

#include <stdbool.h>
#include "asn1/asn1c/IA5String.h"
#include "data_structure/array_list.h"

enum uri_type {
	/* rsync URL */
	UT_RSYNC,
	/* HTTPS URL */
	UT_HTTPS,
	/*
	 * URI (not URL).
	 * In practice it's always rsync, but it doesn't matter.
	 */
	UT_CAGED,
};

struct rpki_uri;

int __uri_create(struct rpki_uri **, enum uri_type, struct rpki_uri *,
    void const *, size_t);
int uri_create(struct rpki_uri **, enum uri_type, struct rpki_uri *,
    char const *);
int uri_create_mft(struct rpki_uri **, struct rpki_uri *, struct rpki_uri *,
    IA5String_t *);

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
bool uri_is_rsync(struct rpki_uri *);
bool uri_is_https(struct rpki_uri *);

char const *uri_val_get_printable(struct rpki_uri *);
char const *uri_op_get_printable(struct rpki_uri *);

char *uri_get_rrdp_workspace(struct rpki_uri *);

/* Plural */

DEFINE_ARRAY_LIST_STRUCT(uri_list, struct rpki_uri *);

void uris_init(struct uri_list *);
void uris_cleanup(struct uri_list *);

void uris_add(struct uri_list *, struct rpki_uri *);

/*
 * The callback should return
 *
 * - 0 on success ("URI handled successfully")
 * - > 0 on soft errors ("Try another URI")
 * - < 0 on hard errors ("Abandon foreach")
 */
typedef int (*uris_dl_cb)(struct rpki_uri *, void *);
int uris_download(struct uri_list *, bool, uris_dl_cb, void *);

#endif /* SRC_TYPES_URI_H_ */
