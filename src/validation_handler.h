#ifndef SRC_VALIDATION_HANDLER_H_
#define SRC_VALIDATION_HANDLER_H_

#include "rtr/db/vrps.h"

void vhandle_init(void);
struct db_table *vhandle_claim(void);

/* Called every time Fort has successfully validated an IPv4 ROA. */
int vhandle_roa_v4(uint32_t, struct ipv4_prefix const *, uint8_t);
/* Called every time Fort has successfully validated an IPv6 ROA. */
int vhandle_roa_v6(uint32_t, struct ipv6_prefix const *, uint8_t);
/* Called every time Fort has successfully validated a BGPsec cert. */
int handle_router_key(unsigned char const *, struct asn_range const *,
    unsigned char const *);

#endif /* SRC_VALIDATION_HANDLER_H_ */
