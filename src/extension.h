#ifndef SRC_EXTENSION_H_
#define SRC_EXTENSION_H_

#include <jansson.h>
#include <openssl/asn1.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <stdbool.h>

struct extension_metadata {
	char const *name;
	int nid;
	bool critical;
	json_t *(*to_json)(void const *);
	void (*destructor)(void *);
};

struct extension_handler {
	struct extension_metadata const *meta;
	bool mandatory;

	int (*cb)(void *, void *);
	void *arg;

	/* For internal use */
	bool found;
};

int extension_init(void);

struct extension_metadata const *ext_bc(void);
struct extension_metadata const *ext_ski(void);
struct extension_metadata const *ext_aki(void);
struct extension_metadata const *ext_ku(void);
struct extension_metadata const *ext_cdp(void);
struct extension_metadata const *ext_aia(void);
struct extension_metadata const *ext_sia(void);
struct extension_metadata const *ext_cp(void);
struct extension_metadata const *ext_ir(void);
struct extension_metadata const *ext_ar(void);
struct extension_metadata const *ext_ir2(void);
struct extension_metadata const *ext_ar2(void);
struct extension_metadata const *ext_cn(void);
struct extension_metadata const *ext_eku(void);

struct extension_metadata const **ext_metadatas(void);

int handle_extensions(struct extension_handler *,
    STACK_OF(X509_EXTENSION) const *);

int cannot_decode(struct extension_metadata const *);
int validate_public_key_hash(X509 *, ASN1_OCTET_STRING *);
int handle_aki(void *, void *);

#endif /* SRC_EXTENSION_H_ */
