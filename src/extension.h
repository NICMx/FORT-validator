#ifndef SRC_EXTENSION_H_
#define SRC_EXTENSION_H_

#include <stdbool.h>
#include <openssl/x509.h>

struct extension_metadata {
	char *name;
	int nid;
	bool critical;
};

struct extension_handler {
	struct extension_metadata const *meta;
	bool mandatory;
	int (*cb)(X509_EXTENSION *, void *);
	void *arg;

	void (*free)(void *);

	/* For internal use */
	bool found;
};

extern const struct extension_metadata BC;
extern const struct extension_metadata SKI;
extern const struct extension_metadata AKI;
extern const struct extension_metadata KU;
extern const struct extension_metadata CDP;
extern const struct extension_metadata AIA;
extern const struct extension_metadata SIA;
extern const struct extension_metadata CP;
extern const struct extension_metadata IR;
extern const struct extension_metadata AR;
extern const struct extension_metadata CN;

int handle_extensions(struct extension_handler *,
    STACK_OF(X509_EXTENSION) const *);

int cannot_decode(struct extension_metadata const *);
int validate_public_key_hash(X509 *, ASN1_OCTET_STRING *);
int handle_aki(X509_EXTENSION *, void *);

#endif /* SRC_EXTENSION_H_ */
