#ifndef SRC_HTTP_HTTP_H_
#define SRC_HTTP_HTTP_H_

#include <stdbool.h>
#include <stddef.h>
#include <curl/curl.h>
#include "types/uri.h"

/* Init on the main process */
int http_init(void);
void http_cleanup(void);

CURL *curl_create(void);
void curl_destroy(CURL *);

int http_get(struct rpki_uri *, long);

int http_direct_download(char const *, char const *);

#endif /* SRC_HTTP_HTTP_H_ */
