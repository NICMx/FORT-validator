#ifndef SRC_HTTP_HTTP_H_
#define SRC_HTTP_HTTP_H_

#include <curl/curl.h>

int http_init(void);
void http_cleanup(void);

int http_download(char const *, char const *, curl_off_t, bool *);
int http_download_direct(char const *, char const *);
int http_download_tmp(char const *, char **, bool *, void *);

#endif /* SRC_HTTP_HTTP_H_ */
