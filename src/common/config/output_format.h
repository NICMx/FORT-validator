#ifndef SRC_CONFIG_OUTPUT_FORMAT_H_
#define SRC_CONFIG_OUTPUT_FORMAT_H_

#include "config/types.h"

enum output_format {
	/* CSV format */
	OFM_CSV,
	/* JSON format */
	OFM_JSON,
};

extern const struct global_type gt_output_format;

#endif /* SRC_CONFIG_OUTPUT_FORMAT_H_ */
