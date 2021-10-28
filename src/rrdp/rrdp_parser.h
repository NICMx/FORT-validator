#ifndef SRC_RRDP_RRDP_PARSER_H_
#define SRC_RRDP_RRDP_PARSER_H_

#include <stdbool.h>
#include "types/uri.h"
#include "rrdp/rrdp_objects.h"
#include "visited_uris.h"

int rrdp_parse_notification(struct rpki_uri *, bool, bool,
    struct update_notification **);
int rrdp_parse_snapshot(struct update_notification *, struct visited_uris *,
    bool);

int rrdp_process_deltas(struct update_notification *,
    unsigned long serial, struct visited_uris *, bool);

#endif /* SRC_RRDP_RRDP_PARSER_H_ */
