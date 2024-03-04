#ifndef SRC_RRDP_H_
#define SRC_RRDP_H_

#include "types/uri.h"

struct cachefile_notification;

int rrdp_update(struct rpki_uri *);

json_t *rrdp_notif2json(struct cachefile_notification *);
int rrdp_json2notif(json_t *, struct cachefile_notification **);

void rrdp_notif_free(struct cachefile_notification *);

#endif /* SRC_RRDP_H_ */
