#ifndef SRC_CONFIG_INIT_TALS_H_
#define SRC_CONFIG_INIT_TALS_H_

#include <stddef.h>
#include <sys/queue.h>
#include "config/types.h"

/* Struct where each URL and its optional message are stored */
struct init_location {
	char *url;
	char *accept_message;
	SLIST_ENTRY(init_location) next;
};

SLIST_HEAD(init_locations, init_location);

extern const struct global_type gt_init_tals_locations;

typedef int (*init_locations_foreach_cb)(char const *, char const *, void *);
int init_locations_foreach(struct init_locations *, init_locations_foreach_cb,
    void *);

int init_locations_init(struct init_locations *, char const *const *, size_t,
    char const *const *, size_t);
void init_locations_cleanup(struct init_locations *);

#endif /* SRC_CONFIG_INIT_TALS_H_ */
