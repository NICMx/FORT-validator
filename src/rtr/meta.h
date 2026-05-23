#ifndef SRC_RTR_META_H_
#define SRC_RTR_META_H_

#include <stdio.h>
#include "types/serial.h"

struct rtr_metadata {
	uint16_t session;

	/*
	 * At least one RTR client implementation (Cloudflare's rpki-rtr-client)
	 * malfunctions if the validator uses zero as the first serial, so this
	 * value behaves as follows:
	 *
	 * serial = 0. After every successful validation cycle, serial++.
	 *
	 * Do not use this value to check whether we already finished our first
	 * validation. (Use base != NULL for that.) Zero is totally a valid
	 * serial, particularly when the integer wraps.
	 */
	serial_t serial;
};

char *rtr_filename(char const *, char const *);
char *rtr_filename2(serial_t, char const *);

void rtr_new_metadata(struct rtr_metadata *);
int rtr_save_metadata(struct rtr_metadata *);
int rtr_load_metadata(struct rtr_metadata *);

int rtr_serial_stat(serial_t serial);

int rtr_open_file(serial_t, char const *, char const *, FILE **);

#endif /* SRC_RTR_META_H_ */
