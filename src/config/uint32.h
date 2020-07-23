#ifndef SRC_CONFIG_UINT32_H_
#define SRC_CONFIG_UINT32_H_

#include "config/types.h"

extern const struct global_type gt_uint32;

void print_uint32(struct option_field const *, void *);
int parse_argv_uint32(struct option_field const *, char const *, void *);
int parse_json_uint32(struct option_field const *, json_t *, void *);

#endif /* SRC_CONFIG_UINT32_H_ */
