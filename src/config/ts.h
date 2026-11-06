#ifndef SRC_CONFIG_TS_H_
#define SRC_CONFIG_TS_H_

#include "config/types.h"

enum ts_type {
	TST_OFF,
	TST_UTC,
	TST_LOCAL,
};

extern const struct global_type gt_timestamp_type;

#endif /* SRC_CONFIG_TS_H_ */
