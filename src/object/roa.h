#ifndef SRC_OBJECT_ROA_H_
#define SRC_OBJECT_ROA_H_

#include <openssl/x509.h>

#include "address.h"
#include "rpp.h"
#include "uri.h"

int roa_traverse(struct rpki_uri const *, struct rpp *, STACK_OF(X509_CRL) *);

int roa_handle_v4(uint32_t, struct ipv4_prefix *, uint8_t);
int roa_handle_v6(uint32_t, struct ipv6_prefix *, uint8_t);

#endif /* SRC_OBJECT_ROA_H_ */
