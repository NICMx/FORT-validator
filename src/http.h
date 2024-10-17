#ifndef SRC_HTTP_H_
#define SRC_HTTP_H_

#include <curl/curl.h>
#include <stdbool.h>

int http_init(void);
void http_cleanup(void);

int http_download(char const *, char const *, curl_off_t, bool *);

#endif /* SRC_HTTP_H_ */
