#ifndef SRC_CONFIG_STR_H_
#define SRC_CONFIG_STR_H_

#include "config/types.h"

extern const struct global_type gt_string;

int parse_toml_string(struct option_field const *, struct toml_table_t *,
    void *);

#endif /* SRC_CONFIG_STR_H_ */
