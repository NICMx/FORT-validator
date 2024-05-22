#ifndef SRC_HASH_H_
#define SRC_HASH_H_

#include "asn1/asn1c/BIT_STRING.h"
#include "types/uri.h"

int hash_validate_mft_file(struct rpki_uri *uri, BIT_STRING_t const *);
int hash_validate_file(struct rpki_uri *, unsigned char const *, size_t);
int hash_validate(char const *, unsigned char const *, size_t,
    unsigned char const *, size_t);
int hash_validate_octet_string(char const *, OCTET_STRING_t const*,
    OCTET_STRING_t const *);

int hash_local_file(char const *, unsigned char *, unsigned int *);

int hash_str(char const *, char const *, unsigned char *, unsigned int *);

#endif /* SRC_HASH_H_ */
