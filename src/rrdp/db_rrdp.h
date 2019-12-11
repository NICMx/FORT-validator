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

rrdp_uri_cmp_result_t db_rrdp_cmp_uri(struct db_rrdp *, char const *,
    char const *, unsigned long);
int db_rrdp_add_uri(struct db_rrdp *, char const *, char const *,
    unsigned long);
int db_rrdp_get_serial(struct db_rrdp *, char const *, unsigned long *);
int db_rrdp_get_last_update(struct db_rrdp *, char const *, long *);

int db_rrdp_set_last_update(struct db_rrdp *, char const *);

bool db_rrdp_get_visited(struct db_rrdp *, char const *);
int db_rrdp_set_visited(struct db_rrdp *, char const *, bool);
int db_rrdp_set_all_nonvisited(struct db_rrdp *);

#endif /* SRC_RRDP_DB_RRDP_H_ */
