#ifndef SRC_CONFIG_LOG_CONF_H_
#define SRC_CONFIG_LOG_CONF_H_

#include "config/types.h"

enum log_level_state {
	LLS_UNSET,
	LLS_DISABLED,
	LLS_ENABLED,
};

struct log_level {
	enum log_level_state state;
	int val; /* Only if state == LLS_ENABLED */
};

extern const struct global_type gt_log_level;

#endif /* SRC_CONFIG_LOG_CONF_H_ */
