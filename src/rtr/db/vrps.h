#ifndef SRC_RTR_DB_VRPS_H_
#define SRC_RTR_DB_VRPS_H_

/*
 * "VRPs" = "Validated ROA Payloads." See RFC 6811.
 *
 * This module stores VRPs and their serials.
 */

#include "rtr/db/deltas_array.h"
#include "types/address.h"
#include "types/asn.h"

int vrps_init(void);
void vrps_destroy(void);

int vrps_update(bool *);

/*
 * The following three functions return -EAGAIN when vrps_update() has never
 * been called, or while it's still building the database.
 * Handle gracefully.
 */

int vrps_foreach_base(vrp_foreach_cb, router_key_foreach_cb, void *);
int vrps_foreach_delta_since(serial_t, serial_t *, delta_vrp_foreach_cb,
    delta_router_key_foreach_cb, void *);
int get_last_serial_number(serial_t *);

int handle_roa_v4(uint32_t, struct ipv4_prefix const *, uint8_t, void *);
int handle_roa_v6(uint32_t, struct ipv6_prefix const *, uint8_t, void *);
int handle_router_key(unsigned char const *, struct asn_range const *,
    unsigned char const *, void *);

uint16_t get_current_session_id(uint8_t);

void vrps_print_base(void);

#endif /* SRC_RTR_DB_VRPS_H_ */
