#ifndef SRC_RTR_COMMON_H_
#define SRC_RTR_COMMON_H_

#include <stdbool.h>
#include <openssl/x509v3.h>

/* "I think that this is not supposed to be implemented." */
#define ENOTSUPPORTED 3172
/* "I haven't implemented this yet." */
#define ENOTIMPLEMENTED 3173

extern char const *repository;
extern size_t repository_len;
extern int NID_rpkiManifest;
extern int NID_signedObject;

#define ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

bool file_has_extension(char const *, size_t, char const *);
int uri_g2l(char const *, size_t, char **);

#endif /* SRC_RTR_COMMON_H_ */
