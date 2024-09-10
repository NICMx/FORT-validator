#ifndef SRC_HASH_H_
#define SRC_HASH_H_

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

struct hash_algorithm;

int hash_setup(void);
void hash_teardown(void);

struct hash_algorithm const *hash_get_sha1(void);
struct hash_algorithm const *hash_get_sha256(void);

int hash_file(struct hash_algorithm const *, char const *, unsigned char *,
    size_t *);

int hash_validate_file(struct hash_algorithm const *, char const *,
    unsigned char const *, size_t);
int hash_validate(struct hash_algorithm const *, unsigned char const *, size_t,
    unsigned char const *, size_t);

char const *hash_get_name(struct hash_algorithm const *);
size_t hash_get_size(struct hash_algorithm const *);

#endif /* SRC_HASH_H_ */
