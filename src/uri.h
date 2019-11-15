#ifndef SRC_URI_H_
#define SRC_URI_H_

#include <stdbool.h>
#include <openssl/x509v3.h>
#include "asn1/asn1c/IA5String.h"

/* Flags to indicate expected uri type */
#define URI_VALID_RSYNC 0x01
#define URI_VALID_HTTPS 0x02

struct rpki_uri;

int uri_create_str(struct rpki_uri **, char const *, size_t);
int uri_create_mixed_str(struct rpki_uri **, char const *, size_t);
int uri_create_mft(struct rpki_uri **, struct rpki_uri *, IA5String_t *);
int uri_create_ad(struct rpki_uri **, ACCESS_DESCRIPTION *, int);

void uri_refget(struct rpki_uri *);
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
bool uri_is_rsync(struct rpki_uri *);

char const *uri_get_printable(struct rpki_uri *);

#endif /* SRC_URI_H_ */
