#ifndef SRC_RRDP_H_
#define SRC_RRDP_H_

#include <jansson.h>
#include <stdbool.h>
#include <time.h>

#include "file.h"
#include "types/uri.h"

struct rrdp_state;

int rrdp_update(struct uri const *, char const *, time_t, bool *,
    struct rrdp_state **);
char const *rrdp_file(struct rrdp_state const *, struct uri const *);

char const *rrdp_create_fallback(char *, struct rrdp_state **,
    struct uri const *);

json_t *rrdp_state2json(struct rrdp_state *);
int rrdp_json2state(json_t *, char *, struct rrdp_state **);

void rrdp_state_free(struct rrdp_state *);

void rrdp_print(struct rrdp_state *);

#endif /* SRC_RRDP_H_ */
