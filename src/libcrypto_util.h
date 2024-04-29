#ifndef SRC_LIBCRYPTO_UTIL_H_
#define SRC_LIBCRYPTO_UTIL_H_

#include <jansson.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

char *bio2str(BIO *);
json_t *bio2json(BIO *);
json_t *oid2json(ASN1_OBJECT const *);
json_t *asn1int2json(ASN1_INTEGER const *);
json_t *asn1str2json(ASN1_STRING const *); /* octet string, bit string, etc */
json_t *asn1time2json(ASN1_TIME const *);
json_t *name2json(X509_NAME const *);
json_t *gn2json(GENERAL_NAME const *);
json_t *gns2json(GENERAL_NAMES const *);
json_t *exts2json(const STACK_OF(X509_EXTENSION) *);

#endif /* SRC_LIBCRYPTO_UTIL_H_ */
