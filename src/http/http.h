#ifndef SRC_HTTP_HTTP_H_
#define SRC_HTTP_HTTP_H_

#include <stddef.h>
#include "uri.h"

/* Init on the main process */
int http_init(void);
void http_cleanup(void);

typedef size_t (http_write_cb)(unsigned char *, size_t, size_t, void *);
int http_download_file(struct rpki_uri *, http_write_cb);
int http_download_file_with_ims(struct rpki_uri *, http_write_cb, long);

#endif /* SRC_HTTP_HTTP_H_ */
