#ifndef SRC_TYPES_URL_H_
#define SRC_TYPES_URL_H_

#include <stdbool.h>

#define RPKI_SCHEMA_LEN 8 /* strlen("rsync://"), strlen("https://") */

char *url_normalize(char const *);
bool url_same_origin(char const *, char const *);

#endif /* SRC_TYPES_URL_H_ */
