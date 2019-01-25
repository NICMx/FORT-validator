#ifndef SRC_RTR_COMMON_H_
#define SRC_RTR_COMMON_H_

#include <stdbool.h>
#include <openssl/x509v3.h>

/* "I think that this is not supposed to be implemented." */
#define ENOTSUPPORTED 3172
/* "I haven't implemented this yet." */
#define ENOTIMPLEMENTED 3173
/*
 * "URI was not RSYNC; ignore it."
 * Not really an error. The RFCs usually declare URI lists; usually only one of
 * them is required to be RSYNC and the others should be skipped (until we
 * start supporting them.)
 */
#define ENOTRSYNC 3174

extern char const *repository;
extern size_t repository_len;
extern int NID_rpkiManifest;
extern int NID_signedObject;
extern int NID_rpkiNotify;

#define ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

int string_clone(void const *, size_t, char **);
int ia5s2string(ASN1_IA5STRING *, char **);

#endif /* SRC_RTR_COMMON_H_ */
