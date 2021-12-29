#ifndef SRC_CONFIG_RSYNC_STRATEGY_H_
#define SRC_CONFIG_RSYNC_STRATEGY_H_

#include "config/types.h"

enum rsync_strategy {
	/**
	 * Strictly correct download strategy.
	 *
	 * The validator will sync each repository publication point separately
	 * as requested by each caRepository contained in the CA certificates'
	 * SIA extensions.
	 */
	RSYNC_STRICT,

	/* The other options have been removed as of Fort 1.6.0. */
};

extern const struct global_type gt_rsync_strategy;

#endif /* SRC_CONFIG_RSYNC_STRATEGY_H_ */
