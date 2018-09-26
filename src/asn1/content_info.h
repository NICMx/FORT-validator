#ifndef SRC_CONTENT_INFO_H_
#define SRC_CONTENT_INFO_H_

/* Some wrappers for libcmscodec's ContentInfo. */

#include <libcmscodec/ContentInfo.h>

int content_info_load(const char *file_name, struct ContentInfo **result);
void content_info_free(struct ContentInfo *info);

#endif /* SRC_CONTENT_INFO_H_ */
