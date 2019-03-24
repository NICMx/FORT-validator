#ifndef SRC_CONFIG_STR_H_
#define SRC_CONFIG_STR_H_

#include "config/types.h"

extern const struct global_type gt_string;

int parse_toml_string(struct toml_table_t *, char const *, char **);

#endif /* SRC_CONFIG_STR_H_ */
