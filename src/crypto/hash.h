#ifndef SRC_HASH_H_
#define SRC_HASH_H_

#include <stdbool.h>
#include <libcmscodec/BIT_STRING.h>
#include <libcmscodec/OBJECT_IDENTIFIER.h>

int hash_init(void);
int hash_is_valid_algorithm(OBJECT_IDENTIFIER_t *, bool *);
int hash_validate_file(char *, BIT_STRING_t *);
int hash_validate_octet_string(OCTET_STRING_t *, OCTET_STRING_t *);

#endif /* SRC_HASH_H_ */
