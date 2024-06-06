#ifndef SRC_HTTP_HTTP_H_
#define SRC_HTTP_HTTP_H_

#include <curl/curl.h>
#include "types/map.h"

int http_init(void);
void http_cleanup(void);

int http_download(struct cache_mapping *, curl_off_t, bool *);
int http_download_direct(char const *, char const *);

#endif /* SRC_HTTP_HTTP_H_ */
