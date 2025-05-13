#ifndef SRC_RTR_DB_VRPS_H_
#define SRC_RTR_DB_VRPS_H_

/*
 * "VRPs" = "Validated ROA Payloads." See RFC 6811.
 *
 * This module stores VRPs and their serials.
 */

#include "types/address.h"
#include "types/asn.h"
#include "types/delta.h"
#include "types/serial.h"

int vrps_init(void);
void vrps_destroy(void);

int vrps_update(bool *);

enum vrps_foreach_base_result {
	VFBR_OK,
	VFBR_UNDER_CONSTRUCTION,
	VFBR_CANT_LOCK,
	VFBR_CB_INTR,
};

enum vrps_foreach_base_result
vrps_foreach_base(vrp_foreach_cb, router_key_foreach_cb, void *);

enum vrps_foreach_delta_since_result {
	VFDSR_OK,
	VFDSR_UNDER_CONSTRUCTION,
	VFDSR_CANT_LOCK,
	VFDSR_INVALID_SERIAL,
	VFDSR_INTR,
};

enum vrps_foreach_delta_since_result
vrps_foreach_delta_since(serial_t, serial_t *, delta_vrp_foreach_cb,
    delta_router_key_foreach_cb, void *);

enum get_last_serial_number_result {
	GLSNR_OK,
	GLSNR_UNDER_CONSTRUCTION,
	GLSNR_CANT_LOCK,
};

enum get_last_serial_number_result get_last_serial_number(serial_t *);

uint16_t get_current_session_id(uint8_t);

void vrps_print_base(void);

#endif /* SRC_RTR_DB_VRPS_H_ */
