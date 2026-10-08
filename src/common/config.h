#ifndef COMMON_CONFIG_H_
#define COMMON_CONFIG_H_

#include "common/config/types.h"

extern struct option_field const options[];

extern const struct global_type gt_callback;

int parse_args(int, char **, void *);
void *get_rpki_config_field(struct option_field const *, void *);
void free_rpki_config(void *);

int handle_help(struct option_field const *, char *);
int handle_usage(struct option_field const *, char *);
int handle_version(struct option_field const *, char *);

#endif /* COMMON_CONFIG_H_ */
