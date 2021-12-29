#ifndef SRC_VALIDATION_HANDLER_H_
#define SRC_VALIDATION_HANDLER_H_

#include "types/address.h"
#include "types/router_key.h"
#include "object/name.h"

/**
 * Functions that handle validation results. It's currently variable so unit
 * tests can easily check traversal.
 *
 * TODO (fine) Review that. It clutters the code too much IMO.
 *
 * All of these functions can be NULL.
 */
struct validation_handler {
	/** Called every time Fort has successfully validated an IPv4 ROA. */
	int (*handle_roa_v4)(uint32_t, struct ipv4_prefix const *, uint8_t,
	    void *);
	/** Called every time Fort has successfully validated an IPv6 ROA. */
	int (*handle_roa_v6)(uint32_t, struct ipv6_prefix const *, uint8_t,
	    void *);
	/** Called every time Fort has successfully validated a BGPsec cert */
	int (*handle_router_key)(unsigned char const *, uint32_t,
	    unsigned char const *, void *);
	/** Generic user-defined argument for the functions above. */
	void *arg;
};

int vhandler_handle_roa_v4(uint32_t, struct ipv4_prefix const *, uint8_t);
int vhandler_handle_roa_v6(uint32_t, struct ipv6_prefix const *, uint8_t);
int vhandler_handle_router_key(unsigned char const *, uint32_t,
    unsigned char const *);

#endif /* SRC_VALIDATION_HANDLER_H_ */
