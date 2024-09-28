#ifndef SRC_RRDP_H_
#define SRC_RRDP_H_

#include <jansson.h>
#include <stdbool.h>
#include <time.h>

#include "types/map.h"

struct rrdp_state;

int rrdp_update(struct cache_mapping *, time_t, bool *, struct rrdp_state **);
char const *rrdp_file(struct rrdp_state *, char const *);

json_t *rrdp_state2json(struct rrdp_state *);
int rrdp_json2state(json_t *, struct rrdp_state **);

void rrdp_state_cleanup(struct rrdp_state *);
void rrdp_state_free(struct rrdp_state *);

#endif /* SRC_RRDP_H_ */
