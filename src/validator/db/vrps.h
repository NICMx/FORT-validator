#ifndef SRC_VRPS_H_
#define SRC_VRPS_H_

/*
 * "VRPs" = "Validated ROA Payloads." See RFC 6811.
 *
 * This module stores VRPs and their serials.
 */

#include "rtr/meta.h"

int vrps_update(struct rtr_metadata *);

#endif /* SRC_VRPS_H_ */
