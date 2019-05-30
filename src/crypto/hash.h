#ifndef SRC_HASH_H_
#define SRC_HASH_H_

#include <stdbool.h>
#include <stddef.h>
#include <libcmscodec/BIT_STRING.h>
#include "uri.h"

int hash_validate_file(char const *, struct rpki_uri *uri,
    BIT_STRING_t const *);
int hash_validate(char const *, unsigned char const *, size_t,
    unsigned char const *, size_t);
int hash_validate_octet_string(char const *, OCTET_STRING_t const*,
    OCTET_STRING_t const *);

#endif /* SRC_HASH_H_ */
