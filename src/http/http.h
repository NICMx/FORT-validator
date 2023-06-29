#ifndef SRC_HTTP_HTTP_H_
#define SRC_HTTP_HTTP_H_

#include <stddef.h>
#include "types/uri.h"

/* Init on the main process */
int http_init(void);
void http_cleanup(void);

int http_download_file(struct rpki_uri *);
int http_download_file_with_ims(struct rpki_uri *, long);

int http_direct_download(char const *, char const *);

#endif /* SRC_HTTP_HTTP_H_ */
