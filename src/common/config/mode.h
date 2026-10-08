#ifndef SRC_CONFIG_MODE_H_
#define SRC_CONFIG_MODE_H_

#include "config/types.h"

/**
 * FORT Run mode
 */
enum mode {
	/* Run as RTR server */
	SERVER,
	/* Run standalone validation (run validation once and exit) */
	STANDALONE,
	/* Print file in standard output */
	PRINT_FILE,
};

extern const struct global_type gt_mode;

#endif /* SRC_CONFIG_MODE_H_ */
