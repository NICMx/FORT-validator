#ifndef COMMON_CONFIG_LOG_CONF_H_
#define COMMON_CONFIG_LOG_CONF_H_

#include "common/config/types.h"

enum log_output {
	SYSLOG,
	CONSOLE
};

extern const struct global_type gt_log_level;
extern const struct global_type gt_log_output;
extern const struct global_type gt_log_facility;

#endif /* COMMON_CONFIG_LOG_CONF_H_ */
