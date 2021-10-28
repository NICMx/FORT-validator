#ifndef SRC_RRDP_RRDP_LOADER_H_
#define SRC_RRDP_RRDP_LOADER_H_

#include <stdbool.h>
#include "types/uri.h"

int rrdp_load(struct rpki_uri *, bool *);
int rrdp_reload_snapshot(struct rpki_uri *);

#endif /* SRC_RRDP_RRDP_LOADER_H_ */
