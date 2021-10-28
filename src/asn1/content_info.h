#ifndef SRC_CONTENT_INFO_H_
#define SRC_CONTENT_INFO_H_

/* Some wrappers for asn1/asn1c/ContentInfo.h. */

#include "types/uri.h"
#include "asn1/asn1c/ContentInfo.h"

int content_info_load(struct rpki_uri *, struct ContentInfo **);
void content_info_free(struct ContentInfo *);

#endif /* SRC_CONTENT_INFO_H_ */
