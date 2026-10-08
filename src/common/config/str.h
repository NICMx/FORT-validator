#ifndef SRC_CONFIG_STR_H_
#define SRC_CONFIG_STR_H_

#include "config/types.h"

extern const struct global_type gt_string;
extern const struct global_type gt_service;

int parse_json_string(json_t *, char const *, char const **);

#endif /* SRC_CONFIG_STR_H_ */
