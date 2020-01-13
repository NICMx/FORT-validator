#ifndef SRC_CONFIG_BOOLEAN_H_
#define SRC_CONFIG_BOOLEAN_H_

#include "config/types.h"

extern const struct global_type gt_bool;

void print_bool(struct option_field const *, void *);
int parse_argv_bool(struct option_field const *, char const *, void *);
int parse_json_bool(struct option_field const *, struct json_t *, void *);

#endif /* SRC_CONFIG_BOOLEAN_H_ */
