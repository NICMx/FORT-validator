#ifndef SRC_BASE64_H_
#define SRC_BASE64_H_

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

bool base64_decode(char *, size_t, unsigned char **, size_t *);

bool base64url_decode(char const *, unsigned char **, size_t *);
bool base64url_encode(unsigned char const *, int, char **);

struct base64decode2file {
	/* libcrypto thingamajig */
	EVP_ENCODE_CTX *decoder;
	/* Because @decoder does not track end of input internally */
	bool done;
	/* Receives bytes from @ctx, so we can then write them to @file */
	unsigned char *buf;
	/* @buf's capacity */
	size_t bufsize;
	/* */
	char *filename;
	/* File where we're writing the decoded data */
	FILE *file;

	EVP_MD_CTX *hasher;
};

int b64d2f_init(struct base64decode2file *, char *);
int b64d2f_write(struct base64decode2file *, unsigned char const *, size_t);
int b64d2f_finish(struct base64decode2file *, unsigned char[EVP_MAX_MD_SIZE]);
void b64d2f_destroy(struct base64decode2file *);

#endif /* SRC_BASE64_H_ */
