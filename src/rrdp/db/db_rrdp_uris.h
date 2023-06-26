#ifndef SRC_RRDP_DB_DB_RRDP_URIS_H_
#define SRC_RRDP_DB_DB_RRDP_URIS_H_

#include <stdbool.h>
#include "rrdp/rrdp_objects.h"
#include "visited_uris.h"

typedef enum {
	RRDP_URI_REQ_ERROR,
	RRDP_URI_REQ_UNVISITED,
	RRDP_URI_REQ_VISITED,
} rrdp_req_status_t;

/*
 * RRDP URI fetched from 'rpkiNotify' OID at a CA certificate, each TAL thread
 * may have a reference to one of these (it holds information such as update
 * notification URI, session ID, serial, visited mft uris).
 */
struct db_rrdp_uri;

struct db_rrdp_uri *db_rrdp_uris_create(void);
void db_rrdp_uris_destroy(struct db_rrdp_uri *);

rrdp_uri_cmp_result_t db_rrdp_uris_cmp(char const *, char const *,
    unsigned long);
void db_rrdp_uris_update(char const *, char const *session_id, unsigned long,
    rrdp_req_status_t, struct visited_uris *);
int db_rrdp_uris_get_serial(char const *, unsigned long *);

int db_rrdp_uris_get_last_update(char const *, long *);
int db_rrdp_uris_set_last_update(char const *);

int db_rrdp_uris_get_request_status(char const *, rrdp_req_status_t *);
int db_rrdp_uris_set_request_status(char const *, rrdp_req_status_t);
void db_rrdp_uris_set_all_unvisited(void);

struct visited_uris *db_rrdp_uris_get_visited_uris(char const *);

int db_rrdp_uris_remove_all_local(struct db_rrdp_uri *, char const *);

char const *db_rrdp_uris_workspace_get(void);
void db_rrdp_uris_workspace_enable(void);
void db_rrdp_uris_workspace_disable(void);

#endif /* SRC_RRDP_DB_DB_RRDP_URIS_H_ */
