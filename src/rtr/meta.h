#ifndef SRC_RTR_META_H_
#define SRC_RTR_META_H_

#include <stdio.h>
#include <time.h>

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

struct rtr_serial {
	serial_t serial;
	struct tm date;
	struct rtr_serial *next;
};

struct rtr_index {
	uint16_t session;
	/*
	 * Linked list; sorted from newest to oldest.
	 *
	 * Can't use SLIST because clean() and expire() want safe traversal
	 * with cursor removals.
	 */
	struct rtr_serial *serials;
};

char *rtr_filename(char const *, char const *);
char *rtr_filename2(serial_t, char const *);

void rtridx_init(struct rtr_index *);
int rtridx_save(struct rtr_index *);
int rtridx_load(struct rtr_index *, bool);
serial_t rtridx_add_serial(struct rtr_index *);
void rtridx_cleanup(struct rtr_index *);
void rtridx_print(struct rtr_index *);

void rtridx_clean(struct rtr_index *);
void rtridx_expire(void);

int rtr_serial_stat(serial_t serial);

int rtr_open_file(serial_t, char const *, char const *, FILE **);

#endif /* SRC_RTR_META_H_ */
