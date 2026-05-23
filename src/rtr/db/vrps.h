#ifndef SRC_VRPS_H_
#define SRC_VRPS_H_

/*
 * "VRPs" = "Validated ROA Payloads." See RFC 6811.
 *
 * This module stores VRPs and their serials.
 */

#include "as_number.h"
#include "rtr/meta.h"
#include "types/address.h"
#include "types/aspa.h"

int vrps_update(struct rtr_metadata *);

int handle_roa_v4(uint32_t, struct ipv4_prefix const *, uint8_t, void *);
int handle_roa_v6(uint32_t, struct ipv6_prefix const *, uint8_t, void *);
int handle_router_key(unsigned char const *, struct asn_range const *,
    unsigned char const *, void *);
int handle_aspa(struct aspa *, void *);

#endif /* SRC_VRPS_H_ */
