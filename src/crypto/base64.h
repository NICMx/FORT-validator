#ifndef SRC_BASE64_H_
#define SRC_BASE64_H_

#include <stdbool.h>
#include <stddef.h>
#include <openssl/bio.h>

int base64_decode(BIO *, unsigned char *, bool, size_t, size_t *);
int base64url_decode(char const *, unsigned char **, size_t *);

int base64url_encode(unsigned char const *, int, char **);

#endif /* SRC_BASE64_H_ */
