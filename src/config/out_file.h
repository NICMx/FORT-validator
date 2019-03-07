#ifndef SRC_CONFIG_OUT_FILE_H_
#define SRC_CONFIG_OUT_FILE_H_

#include <stdio.h>
#include "config/types.h"

struct config_out_file {
	FILE *fd;
	char *file_name;
};

extern const struct global_type gt_out_file;

#endif /* SRC_CONFIG_OUT_FILE_H_ */
