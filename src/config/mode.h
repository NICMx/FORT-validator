#ifndef SRC_CONFIG_MODE_H_
#define SRC_CONFIG_MODE_H_

#include "config/types.h"

/**
 * FORT Run mode
 */
enum mode {
	/**
	 * Run as an RTR server
	 */
	SERVER,
	/*
	 * Run standalone validation (run validation once and exit)
	 */
	STANDALONE,
};

extern const struct global_type gt_mode;

#endif /* SRC_CONFIG_MODE_H_ */
