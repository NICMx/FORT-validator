#ifndef SRC_HASH_H_
#define SRC_HASH_H_

#include <stdbool.h>
#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

/*
 * TODO (fine) Delete this structure (use md directly) once OpenSSL < 3 support
 * is dropped.
 */
struct hash_algorithm {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MD *md;
#else
	EVP_MD const *md;
#endif
	size_t size;
	char const *name;
};

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

/* TODO (fine) move to RRDP? */
#define RRDP_HASH_LEN SHA256_DIGEST_LENGTH
struct rrdp_hash {
	unsigned char bytes[RRDP_HASH_LEN];
	bool set;				/* Initialized? */
};

int str2hash(char const *, size_t, struct rrdp_hash *);
void hash_print(struct rrdp_hash *);

EVP_MD_CTX *sha256_create(void);
int sha256_init(EVP_MD_CTX *);
int sha256_update(EVP_MD_CTX *, void const *, size_t);
int sha256_finish(EVP_MD_CTX *, unsigned char *);

int sha256_check(EVP_MD_CTX *, unsigned char const *, char const *, char const *);
#define sha256_destroy(h) EVP_MD_CTX_free(h)

#endif /* SRC_HASH_H_ */
