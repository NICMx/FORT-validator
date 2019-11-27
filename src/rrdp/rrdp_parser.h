#ifndef SRC_RRDP_RRDP_PARSER_H_
#define SRC_RRDP_RRDP_PARSER_H_

#include "rrdp/rrdp_objects.h"
#include "uri.h"

int rrdp_parse_notification(struct rpki_uri *, struct update_notification **);
int rrdp_parse_snapshot(struct update_notification *, struct snapshot **);

#endif /* SRC_RRDP_RRDP_PARSER_H_ */
