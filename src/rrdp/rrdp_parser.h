#ifndef SRC_RRDP_RRDP_PARSER_H_
#define SRC_RRDP_RRDP_PARSER_H_

#include "rrdp/rrdp_objects.h"
#include "uri.h"
#include "visited_uris.h"

int rrdp_parse_notification(struct rpki_uri *, struct update_notification **);
int rrdp_parse_snapshot(struct update_notification *, struct visited_uris *);

int rrdp_process_deltas(struct update_notification *,
    unsigned long serial, struct visited_uris *);

#endif /* SRC_RRDP_RRDP_PARSER_H_ */
