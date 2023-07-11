#ifndef SRC_HTTP_HTTP_H_
#define SRC_HTTP_HTTP_H_

#include "types/uri.h"

int http_init(void);
void http_cleanup(void);

int http_download(struct rpki_uri *, bool *);
int http_direct_download(char const *, char const *);

#endif /* SRC_HTTP_HTTP_H_ */
