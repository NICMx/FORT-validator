#ifndef SRC_TYPES_URI_H_
#define SRC_TYPES_URI_H_

#include <stdbool.h>
#include "file.h"
#include "asn1/asn1c/IA5String.h"

#define URI_ALLOW_RSYNC (1 << 0)
#define URI_ALLOW_HTTP (1 << 1)

#define ENOTCHANGED 95094509

struct rpki_uri;

/*
 * Straightforward HTTP = Downloads with no fuss.
 *
 * Caged HTTP = Downloads into a Notification-specific namespace. See
 * https://mailarchive.ietf.org/arch/msg/sidrops/FrAjMFWY5a_cofpOoCEO5Yr_ZLI/
 */
enum rpki_uri_type {
	/* rsync or straightforward HTTP */
	URI_TYPE_VERSATILE,
	/* rsync only */
	URI_TYPE_RSYNC,
	/* Straightforward HTTP only */
	URI_TYPE_HTTP_SIMPLE,
	/* Caged HTTP only */
	URI_TYPE_HTTP_CAGED,
	/* Never downloaded (simply used to reference some other rpki_uri) */
	URI_TYPE_VOID,
};

int uri_create(char *, enum rpki_uri_type, struct rpki_uri **);
int uri_create_caged(char *, struct rpki_uri *, struct rpki_uri **);
int uri_create_mft(struct rpki_uri *, IA5String_t *, struct rpki_uri **);

void uri_refget(struct rpki_uri *);
void uri_refput(struct rpki_uri *);

char const *uri_get_global(struct rpki_uri *);
char const *uri_get_local(struct rpki_uri *);
enum rpki_uri_type uri_get_type(struct rpki_uri *);

bool uri_has_extension(struct rpki_uri *, char const *);
bool uri_is_certificate(struct rpki_uri *);

char const *uri_val_get_printable(struct rpki_uri *);
char const *uri_op_get_printable(struct rpki_uri *);

#endif /* SRC_TYPES_URI_H_ */
