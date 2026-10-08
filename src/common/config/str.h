#ifndef COMMON_CONFIG_STR_H_
#define COMMON_CONFIG_STR_H_

#include "common/config/types.h"

extern const struct global_type gt_string;
extern const struct global_type gt_service;

int parse_json_string(json_t *, char const *, char const **);

#endif /* COMMON_CONFIG_STR_H_ */
