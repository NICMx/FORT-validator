#ifndef SRC_BASE64_H_
#define SRC_BASE64_H_

#include <openssl/bio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

int base64_decode(BIO *, unsigned char *, bool, size_t, size_t *);
int base64url_decode(char const *, unsigned char **, size_t *);

int base64url_encode(unsigned char const *, int, char **);

#endif /* SRC_BASE64_H_ */
