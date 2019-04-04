#ifndef SRC_CONFIG_UINT_H_
#define SRC_CONFIG_UINT_H_

#include "config/types.h"

extern const struct global_type gt_u_int;

int parse_argv_u_int(struct option_field const *, char const *, void *);
int parse_json_u_int(struct option_field const *, struct json_t *, void *);

#endif /* SRC_CONFIG_UINT_H_ */
