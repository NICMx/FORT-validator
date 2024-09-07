#ifndef SRC_RPP_H_
#define SRC_RPP_H_

#include <openssl/safestack.h>
#include <openssl/x509.h>

#include "types/map.h"

struct rpp;

struct rpp *rpp_create(void);
void rpp_refget(struct rpp *);
void rpp_refput(struct rpp *);

int rpp_add_file(struct rpp *, struct cache_mapping *);

char const *rpp_get_crl_url(struct rpp const *);
STACK_OF(X509_CRL) *rpp_crl(struct rpp *);

void rpp_traverse(struct rpp *);

#endif /* SRC_RPP_H_ */
