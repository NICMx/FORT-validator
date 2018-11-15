#ifndef SRC_RTR_COMMON_H_
#define SRC_RTR_COMMON_H_

#include <stdbool.h>
#include <openssl/x509v3.h>
#include "state.h"

/* "I think that this is not supposed to be implemented." */
#define ENOTSUPPORTED 3172
/* "I haven't implemented this yet." */
#define ENOTIMPLEMENTED 3173

extern char const *repository;
extern int NID_rpkiManifest;
extern int NID_rpkiNotify;

#define ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

bool file_has_extension(char const *, char const *);
int uri_g2l(struct validation *, char const *, char **);
int gn2uri(struct validation *, GENERAL_NAME *, char const **);

#endif /* SRC_RTR_COMMON_H_ */
