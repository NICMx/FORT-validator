#ifndef SRC_BASE64_H_
#define SRC_BASE64_H_

#include <openssl/bio.h>
#include <stdbool.h>
#include <stddef.h>

bool base64_decode(BIO *, unsigned char *, bool, size_t, size_t *);
bool base64url_decode(char const *, unsigned char **, size_t *);

bool base64url_encode(unsigned char const *, int, char **);

#endif /* SRC_BASE64_H_ */
