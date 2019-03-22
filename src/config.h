#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdbool.h>

#include "config/filename_format.h"
#include "config/sync_strategy.h"
#include "config/string_array.h"
#include "config/types.h"

/* Init/destroy */
int handle_flags_config(int , char **);
void free_rpki_config(void);

/* Getters */
char const *config_get_tal(void);
char const *config_get_local_repository(void);
enum sync_strategy config_get_sync_strategy(void);
bool config_get_shuffle_uris(void);
unsigned int config_get_max_cert_depth(void);
bool config_get_color_output(void);
enum filename_format config_get_filename_format(void);
FILE *config_get_roa_output(void);
char *config_get_rsync_program(void);
struct string_array const *config_get_rsync_args(bool);

/* Needed public by the TOML module */
void *get_rpki_config_field(struct option_field const *);
void get_group_fields(struct group_fields const **);

#endif /* SRC_CONFIG_H_ */
