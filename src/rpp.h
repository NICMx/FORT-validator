#ifndef SRC_RPP_H_
#define SRC_RPP_H_

#include <openssl/safestack.h>
#include <openssl/x509.h>

struct rpp;

struct rpp *rpp_create(void);
void rpp_refget(struct rpp *pp);
void rpp_refput(struct rpp *pp);

void rpp_add_cert(struct rpp *, char *);
int rpp_add_crl(struct rpp *, char *);
void rpp_add_roa(struct rpp *, char *);
void rpp_add_ghostbusters(struct rpp *, char *);

char const *rpp_get_crl(struct rpp const *);
int rpp_crl(struct rpp *, STACK_OF(X509_CRL) **);

void rpp_traverse(struct rpp *);

#endif /* SRC_RPP_H_ */
