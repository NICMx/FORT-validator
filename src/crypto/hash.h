#ifndef SRC_HASH_H_
#define SRC_HASH_H_

#include <stdbool.h>
#include <stddef.h>
#include <libcmscodec/BIT_STRING.h>
#include <libcmscodec/OBJECT_IDENTIFIER.h>

int hash_is_sha256(OBJECT_IDENTIFIER_t *, bool *);
int hash_validate_file(char const *, char const *, BIT_STRING_t const *);
int hash_validate(char const *, unsigned char const *, size_t,
    unsigned char const *, size_t);
int hash_validate_octet_string(char const *, OCTET_STRING_t const*,
    OCTET_STRING_t const *);

#endif /* SRC_HASH_H_ */
