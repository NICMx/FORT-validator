#ifndef SRC_RRDP_RRDP_PARSER_H_
#define SRC_RRDP_RRDP_PARSER_H_

#include "types/uri.h"
#include "rrdp/rrdp_objects.h"

int rrdp_parse_notification(struct rpki_uri *, struct update_notification *);
int rrdp_parse_snapshot(struct update_notification *);
int rrdp_process_deltas(struct update_notification *, unsigned long);

#endif /* SRC_RRDP_RRDP_PARSER_H_ */
