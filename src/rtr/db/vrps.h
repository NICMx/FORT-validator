#ifndef SRC_VRPS_H_
#define SRC_VRPS_H_

#include <time.h>
#include <netinet/ip.h>
#include "rtr/db/delta.h"
#include "rtr/db/roa_tree.h"

enum delta_status {
	/** There's no data at the DB */
	DS_NO_DATA_AVAILABLE,
	/** The diff can't be determined */
	DS_DIFF_UNDETERMINED,
	/** There's no difference */
	DS_NO_DIFF,
	/** There are diffs between SERIAL and the last DB serial */
	DS_DIFF_AVAILABLE,
};

int vrps_init(void);
void vrps_destroy(void);

int vrps_update(struct roa_tree *, struct deltas *);
enum delta_status deltas_db_status(uint32_t *);

int vrps_foreach_base_roa(vrp_foreach_cb, void *);
int vrps_foreach_delta_roa(uint32_t, uint32_t, vrp_foreach_cb, void *);

uint32_t get_last_serial_number(void);
uint16_t get_current_session_id(uint8_t);

#endif /* SRC_VRPS_H_ */
