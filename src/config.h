#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdbool.h>
#include <stdint.h>

#include "config/filename_format.h"
#include "config/log_conf.h"
#include "config/mode.h"
#include "config/rsync_strategy.h"
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
unsigned int config_get_interval_refresh(void);
unsigned int config_get_interval_retry(void);
unsigned int config_get_interval_expire(void);
char const *config_get_slurm(void);

char const *config_get_tal(void);
char const *config_get_local_repository(void);
bool config_get_shuffle_tal_uris(void);
unsigned int config_get_max_cert_depth(void);
enum mode config_get_mode(void);
bool config_get_work_offline(void);
char const *config_get_http_user_agent(void);
unsigned int config_get_http_connect_timeout(void);
unsigned int config_get_http_transfer_timeout(void);
unsigned int config_get_http_idle_timeout(void);
char const *config_get_http_ca_path(void);
bool config_get_rsync_enabled(void);
unsigned int config_get_rsync_priority(void);
enum rsync_strategy config_get_rsync_strategy(void);
unsigned int config_get_rsync_retry_count(void);
unsigned int config_get_rsync_retry_interval(void);
char *config_get_rsync_program(void);
struct string_array const *config_get_rsync_args(bool);
bool config_get_rrdp_enabled(void);
unsigned int config_get_rrdp_priority(void);
unsigned int config_get_rrdp_retry_count(void);
unsigned int config_get_rrdp_retry_interval(void);
char const *config_get_output_roa(void);
char const *config_get_output_bgpsec(void);
unsigned int config_get_asn1_decode_max_stack(void);
unsigned int config_get_stale_repository_period(void);

/* Logging getters */
bool config_get_op_log_enabled(void);
char const * config_get_op_log_prefix(void);
bool config_get_op_log_color_output(void);
enum filename_format config_get_op_log_filename_format(void);
uint8_t config_get_op_log_level(void);
enum log_output config_get_op_log_output(void);
uint32_t config_get_op_log_facility(void);

bool config_get_val_log_enabled(void);
char const * config_get_val_log_prefix(void);
bool config_get_val_log_color_output(void);
enum filename_format config_get_val_log_filename_format(void);
uint8_t config_get_val_log_level(void);
enum log_output config_get_val_log_output(void);
uint32_t config_get_val_log_facility(void);

/*
 * Public, so that work-offline can set them, or (to be deprecated)
 * sync-strategy when set to 'off'.
 */
void config_set_rsync_enabled(bool);
void config_set_rrdp_enabled(bool);

/* FIXME (later) Remove when sync-strategy is fully deprecated */
void config_set_sync_strategy(enum rsync_strategy);
void config_set_rsync_strategy(enum rsync_strategy);

/* Needed public by the JSON module */
void *get_rpki_config_field(struct option_field const *);
struct option_field const *get_option_metadatas(void);

#endif /* SRC_CONFIG_H_ */
