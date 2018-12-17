#ifndef SRC_HASH_H_
#define SRC_HASH_H_

#include <libcmscodec/BIT_STRING.h>

int hash_init(void);
int hash_validate(char *file, BIT_STRING_t *hash);

#endif /* SRC_HASH_H_ */
