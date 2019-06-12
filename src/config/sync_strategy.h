#ifndef SRC_CONFIG_SYNC_STRATEGY_H_
#define SRC_CONFIG_SYNC_STRATEGY_H_

#include "config/types.h"

/**
 * Note: The only repository synchronization protocol implemented so far is
 * RSYNC. Whenever you see "sync", think "rsync."
 */
enum sync_strategy {
	/**
	 * Synchronization is turned off.
	 * The validator will work on an already downloaded repository.
	 */
	SYNC_OFF,
	/**
	 * Strictly correct download strategy.
	 *
	 * The validator will sync each repository publication point separately
	 * as requested by each caRepository contained in the CA certificates'
	 * SIA extensions.
	 *
	 * No risk of downloading unneeded files, but otherwise slow, as every
	 * different repository publication point requires a separate sync call.
	 *
	 * In order to enable this strategy, compile using the flag:
	 * ENABLE_STRICT_STRATEGY
	 */
	SYNC_STRICT,
	/**
	 * Always download the likely root of the entire repository.
	 *
	 * For example, if we get the following caRepositories:
	 *
	 * - `rsync://a.b.c/d/e/f/g/h/i`
	 * - `rsync://a.b.c/d/e/f/g/h/j`
	 * - `rsync://a.b.c/d/e/f/k`
	 *
	 * This strategy will synchronize `rsync://a.b.c/d` while parsing the
	 * first caRepository, and then skip synchronization during the second
	 * and third ones. (Because they are already downloaded.)
	 *
	 * This strategy risks downloading unneeded files, and even failing due
	 * to lack of read permissions on stray subdirectories. On the flip
	 * side, if the repository holds no unnecessary subdirectories, then
	 * this strategy is the fastest one, since it generally only requires
	 * one sync call per domain, which often translates into one sync call
	 * per validation cycle.
	 *
	 * Currently, all of the official repositories are actually specifically
	 * structured to benefit this strategy.
	 */
	SYNC_ROOT,
	/**
	 * Same as SYNC_ROOT, except the root certificate is synchronized
	 * separately.
	 * (Either because it's in a separate directory, or because we don't
	 * want to download its entire repository until we've verified its
	 * legitimacy and integrity.)
	 */
	SYNC_ROOT_EXCEPT_TA,
};

extern const struct global_type gt_sync_strategy;

#endif /* SRC_CONFIG_SYNC_STRATEGY_H_ */
