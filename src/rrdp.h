#ifndef SRC_RRDP_H_
#define SRC_RRDP_H_

#include <jansson.h>

struct cachefile_notification;
struct cache_node;

int rrdp_update(char const *, struct cache_node *);

json_t *rrdp_notif2json(struct cachefile_notification *);
int rrdp_json2notif(json_t *, struct cachefile_notification **);

void rrdp_notif_free(struct cachefile_notification *);

#endif /* SRC_RRDP_H_ */
