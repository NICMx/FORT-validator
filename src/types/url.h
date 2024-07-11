#ifndef SRC_TYPES_URL_H_
#define SRC_TYPES_URL_H_

#define RPKI_SCHEMA_LEN 8 /* strlen("rsync://"), strlen("https://") */

char *url_normalize(char const *);

#endif /* SRC_TYPES_URL_H_ */
