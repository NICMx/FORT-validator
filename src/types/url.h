#ifndef SRC_TYPES_URL_H_
#define SRC_TYPES_URL_H_

#include <stdbool.h>

#define RPKI_SCHEMA_LEN 8 /* strlen("rsync://"), strlen("https://") */

bool url_is_rsync(char const *);
bool url_is_https(char const *);

char *url_normalize(char const *);
char *url_parent(char const *);
bool url_same_origin(char const *, char const *);

#endif /* SRC_TYPES_URL_H_ */
