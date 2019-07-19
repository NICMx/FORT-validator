#ifndef SRC_VALIDATION_HANDLER_H_
#define SRC_VALIDATION_HANDLER_H_

#include "address.h"
#include "object/name.h"
#include "object/router_key.h"

/**
 * Functions that handle validation results.
 *
 * At some point, I believe we will end up separating the validator code into a
 * library, so it can be used by other applications aside from Fort's RTR
 * server.
 *
 * This structure is designed with that in mind; it's the callback collection
 * that the library's user application will fill up, so it can do whatever it
 * wants with the validated ROAs.
 *
 * Because it's intended to be used by arbitrary applications, it needs to be
 * generic. Please refrain from adding callbacks that are specifically meant for
 * a particular use case.
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
	int (*handle_bgpsec)(unsigned char const *, uint32_t,
	    unsigned char const *, size_t, void *);
	/** Generic user-defined argument for the functions above. */
	void *arg;
};

int vhandler_handle_roa_v4(uint32_t, struct ipv4_prefix const *, uint8_t);
int vhandler_handle_roa_v6(uint32_t, struct ipv6_prefix const *, uint8_t);
int vhandler_handle_bgpsec(unsigned char const *, uint32_t,
    unsigned char const *, size_t);

#endif /* SRC_VALIDATION_HANDLER_H_ */
