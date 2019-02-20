#ifndef SRC_RPP_H_
#define SRC_RPP_H_

#include "uri.h"

struct rpp;

struct rpp *rpp_create(void);
void rpp_destroy(struct rpp *);

int rpp_add_cert(struct rpp *, struct rpki_uri *);
int rpp_add_crl(struct rpp *, struct rpki_uri *);
int rpp_add_roa(struct rpp *, struct rpki_uri *);
int rpp_add_ghostbusters(struct rpp *, struct rpki_uri *);

struct rpki_uri const *rpp_get_crl(struct rpp const *);

int rpp_traverse(struct rpp *);

#endif /* SRC_RPP_H_ */
