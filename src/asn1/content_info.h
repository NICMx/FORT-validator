#ifndef SRC_CONTENT_INFO_H_
#define SRC_CONTENT_INFO_H_

/* Some wrappers for libcmscodec's ContentInfo. */

#include <libcmscodec/ContentInfo.h>
#include "uri.h"

int content_info_load(struct rpki_uri const *, struct ContentInfo **);
void content_info_free(struct ContentInfo *);

#endif /* SRC_CONTENT_INFO_H_ */
