#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdbool.h>
#include <stdint.h>

#include "config/filename_format.h"
#include "config/mode.h"
#include "config/sync_strategy.h"
#include "config/string_array.h"
#include "config/types.h"

/* Init/destroy */
int handle_flags_config(int , char **);
void free_rpki_config(void);

/* Getters */
char const *config_get_server_address(void);
char const *config_get_server_port(void);
int config_get_server_queue(void);
unsigned int config_get_validation_interval(void);
char const *config_get_slurm(void);

char const *config_get_tal(void);
char const *config_get_local_repository(void);
enum sync_strategy config_get_sync_strategy(void);
bool config_get_shuffle_tal_uris(void);
unsigned int config_get_max_cert_depth(void);
enum mode config_get_mode(void);
bool config_get_color_output(void);
enum filename_format config_get_filename_format(void);
char *config_get_rsync_program(void);
struct string_array const *config_get_rsync_args(bool);
char const *config_get_output_roa(void);

/* Needed public by the JSON module */
void *get_rpki_config_field(struct option_field const *);
struct option_field const *get_option_metadatas(void);

#endif /* SRC_CONFIG_H_ */
