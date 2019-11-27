#ifndef SRC_RRDP_DB_RRDP_H_
#define SRC_RRDP_DB_RRDP_H_

#include "rrdp/rrdp_objects.h"

/*
 * Struct and methods to persist RRDP information, such as URIs, session ID per
 * URI and current serial number.
 */
struct db_rrdp;

int db_rrdp_create(struct db_rrdp **);
void db_rddp_destroy(struct db_rrdp *);

enum rrdp_uri_cmp_result db_rrdp_cmp_uri(struct db_rrdp *, char const *,
    char const *, unsigned long);
int db_rrdp_add_uri(struct db_rrdp *, char const *, char const *,
    unsigned long);

#endif /* SRC_RRDP_DB_RRDP_H_ */
