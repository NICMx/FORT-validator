#ifndef SRC_TYPES_STR_H_
#define SRC_TYPES_STR_H_

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <stdbool.h>

#include "types/arraylist.h"

char *str_concat(char const *, char const *);

int hex2ulong(char const *, unsigned long *);

int ia5s2string(ASN1_IA5STRING *, char **);
int BN2string(BIGNUM *, char **);

/**
 * Do not modify fields directly; this should be private.
 *
 * This is more or less like strtok(), except it doesn't modify the string at
 * any point.
 */
struct string_tokenizer {
	/** String we're tokenizing. */
	char const *str;
	size_t str_len;
	/** Token delimiter. */
	unsigned char separator;
	/** Offset of the first character of the current token. */
	size_t start;
	/** Offset of the last character of the current token + 1. */
	size_t end;
};

void string_tokenizer_init(struct string_tokenizer *, char const *, size_t,
    unsigned char);
bool string_tokenizer_next(struct string_tokenizer *);
bool token_equals(struct string_tokenizer *, struct string_tokenizer *);
char *token_read(struct string_tokenizer *);
size_t token_count(struct string_tokenizer *);

/* Plural */

DEFINE_ARRAY_LIST_STRUCT(strlist, char *);

void strlist_init(struct strlist *);
void strlist_cleanup(struct strlist *);
void strlist_add(struct strlist *, char *);

#endif /* SRC_TYPES_STR_H_ */
