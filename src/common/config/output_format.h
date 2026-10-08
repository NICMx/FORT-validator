#ifndef COMMON_CONFIG_OUTPUT_FORMAT_H_
#define COMMON_CONFIG_OUTPUT_FORMAT_H_

#include "common/config/types.h"

enum output_format {
	/* CSV format */
	OFM_CSV,
	/* JSON format */
	OFM_JSON,
};

extern const struct global_type gt_output_format;

#endif /* COMMON_CONFIG_OUTPUT_FORMAT_H_ */
