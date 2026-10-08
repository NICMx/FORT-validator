#ifndef SRC_HTTP_H_
#define SRC_HTTP_H_

#include <curl/curl.h>

#include "types/uri.h"

int http_init(void);
void http_cleanup(void);

int http_download(struct uri const *, curl_write_callback, void *,
    curl_off_t, bool *);

#endif /* SRC_HTTP_H_ */
