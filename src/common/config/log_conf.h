#ifndef SRC_CONFIG_LOG_CONF_H_
#define SRC_CONFIG_LOG_CONF_H_

#include "config/types.h"

enum log_output {
	SYSLOG,
	CONSOLE
};

extern const struct global_type gt_log_level;
extern const struct global_type gt_log_output;
extern const struct global_type gt_log_facility;

#endif /* SRC_CONFIG_LOG_CONF_H_ */
