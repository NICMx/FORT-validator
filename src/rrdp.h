#ifndef SRC_RRDP_H_
#define SRC_RRDP_H_

#include "types/map.h"

struct cachefile_notification;

int rrdp_update(struct cache_mapping *);

json_t *rrdp_notif2json(struct cachefile_notification *);
int rrdp_json2notif(json_t *, struct cachefile_notification **);

void rrdp_notif_free(struct cachefile_notification *);

#endif /* SRC_RRDP_H_ */
