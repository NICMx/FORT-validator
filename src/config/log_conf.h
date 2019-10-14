#ifndef SRC_CONFIG_LOG_CONF_H_
#define SRC_CONFIG_LOG_CONF_H_

#include "config/types.h"

enum log_level {
	LOG_LEVEL_ERROR,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_INFO,
	LOG_LEVEL_DEBUG
};

enum log_output {
	SYSLOG,
	CONSOLE
};

extern const struct global_type gt_log_level;
extern const struct global_type gt_log_output;

#endif /* SRC_CONFIG_LOG_CONF_H_ */
