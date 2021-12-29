#ifndef SRC_RPP_RPP_DL_STATUS_H_
#define SRC_RPP_RPP_DL_STATUS_H_

#include "types/uri.h"

enum rpp_download_status {
	/* Has not been downloaded in the current iteration. */
	RDS_NOT_YET,
	/* Already downloaded successfully in the current iteration. */
	RDS_SUCCESS,
	/* Download already attempted; it didn't work, do not retry. */
	RDS_ERROR,
};

/*
 * A table that stores the download status of each RPP during each validation
 * run. It's meant to prevent us from accidentally downloading an RPP twice
 * in quick succession.
 *
 * Only exists during validation runs.
 */
struct rpp_dl_status_db;

struct rpp_dl_status_db *rdsdb_create(void);
void rdsdb_destroy(struct rpp_dl_status_db *);

enum rpp_download_status rdsdb_get(struct rpki_uri *);
void rdsdb_set(struct rpki_uri *, int);

#endif /* SRC_RPP_RPP_DL_STATUS_H_ */
