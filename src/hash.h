#ifndef SRC_HASH_H_
#define SRC_HASH_H_

#include <stdbool.h>
#include <stddef.h>
#include <openssl/sha.h>

struct hash_algorithm;

int hash_setup(void);
void hash_teardown(void);

struct hash_algorithm const *hash_get_sha1(void);
struct hash_algorithm const *hash_get_sha256(void);

int hash_file(struct hash_algorithm const *, char const *,
    unsigned char *, size_t *);
int hash_buffer(struct hash_algorithm const *, unsigned char const *, size_t,
    unsigned char *, size_t);

int hash_validate_file(struct hash_algorithm const *, char const *,
    unsigned char const *, size_t);
int hash_validate(struct hash_algorithm const *, unsigned char const *, size_t,
    unsigned char const *, size_t);

char const *hash_get_name(struct hash_algorithm const *);
size_t hash_get_size(struct hash_algorithm const *);

#define RRDP_HASH_LEN SHA256_DIGEST_LENGTH
struct rrdp_hash {
	unsigned char bytes[RRDP_HASH_LEN];
	bool set;				/* Initialized? */
};

int str2hash(char const *, struct rrdp_hash *);

#endif /* SRC_HASH_H_ */
