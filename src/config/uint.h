#ifndef SRC_CONFIG_UINT_H_
#define SRC_CONFIG_UINT_H_

#include "config/types.h"

extern const struct global_type gt_uint;

void print_uint(struct option_field const *, void *);
int parse_argv_uint(struct option_field const *, char const *, void *);
int parse_json_uint(struct option_field const *, struct json_t *, void *);

#endif /* SRC_CONFIG_UINT_H_ */
