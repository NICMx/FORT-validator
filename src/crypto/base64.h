#ifndef SRC_BASE64_H_
#define SRC_BASE64_H_

#include <stddef.h>
#include <openssl/bio.h>

int base64_decode(BIO *, unsigned char *, size_t, size_t *);

#endif /* SRC_BASE64_H_ */
