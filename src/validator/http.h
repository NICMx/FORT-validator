#ifndef VALIDATOR_HTTP_H_
#define VALIDATOR_HTTP_H_

#include <curl/curl.h>

#include "common/types/uri.h"

int http_init(void);
void http_cleanup(void);

int http_download(struct uri const *, curl_write_callback, void *,
    curl_off_t, bool *);

#endif /* VALIDATOR_HTTP_H_ */
