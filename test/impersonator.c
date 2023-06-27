#include <arpa/inet.h>

#include "config.h"
#include "incidence/incidence.h"

/**
 * Some core functions, as linked from unit testing code.
 */

static char addr_buffer1[INET6_ADDRSTRLEN];
static char addr_buffer2[INET6_ADDRSTRLEN];

static unsigned int http_priority = 60;
static unsigned int rsync_priority = 50;

char const *
v4addr2str(struct in_addr const *addr)
{
	return inet_ntop(AF_INET, addr, addr_buffer1, sizeof(addr_buffer1));
}

char const *
v4addr2str2(struct in_addr const *addr)
{
	return inet_ntop(AF_INET, addr, addr_buffer2, sizeof(addr_buffer2));
}

char const *
v6addr2str(struct in6_addr const *addr)
{
	return inet_ntop(AF_INET6, addr, addr_buffer1, sizeof(addr_buffer1));
}

char const *
v6addr2str2(struct in6_addr const *addr)
{
	return inet_ntop(AF_INET6, addr, addr_buffer2, sizeof(addr_buffer2));
}

char const *
fnstack_peek(void)
{
	return NULL;
}

void
reqs_errors_log_summary(void)
{
	/* Nothing here */
}

char const *
config_get_tal(void)
{
	return "tal/";
}

bool
config_get_shuffle_tal_uris(void)
{
	return false;
}

char const *
config_get_local_repository(void)
{
	return "repository/";
}

enum rsync_strategy
config_get_rsync_strategy(void)
{
	return RSYNC_ROOT;
}

bool
config_get_rsync_enabled(void)
{
	return true;
}

unsigned int
config_get_rsync_priority(void)
{
	return rsync_priority;
}

unsigned int
config_get_http_priority(void)
{
	return http_priority;
}

char const *
config_get_slurm(void)
{
	return NULL;
}

enum mode
config_get_mode(void)
{
	return STANDALONE;
}

char const *
config_get_output_roa(void)
{
	return NULL;
}

char const *
config_get_output_bgpsec(void)
{
	return NULL;
}

bool
config_get_op_log_enabled(void)
{
	return true;
}

char const *
config_get_op_log_tag(void)
{
	return NULL;
}

bool
config_get_op_log_color_output(void)
{
	return false;
}

enum filename_format
config_get_op_log_filename_format(void)
{
	return FNF_NAME;
}

uint8_t
config_get_op_log_level(void)
{
	return 3; /* LOG_ERR */
}

enum log_output
config_get_op_log_output(void)
{
	return CONSOLE;
}

uint32_t
config_get_op_log_facility(void)
{
	return (3<<3); /* LOG_DAEMON */
}

bool
config_get_val_log_enabled(void)
{
	return true;
}

char const *
config_get_val_log_tag(void)
{
	return "VALIDATION";
}

bool
config_get_val_log_color_output(void)
{
	return false;
}

enum filename_format
config_get_val_log_filename_format(void)
{
	return FNF_NAME;
}

uint8_t
config_get_val_log_level(void)
{
	return 3; /* LOG_ERR */
}

enum log_output
config_get_val_log_output(void)
{
	return CONSOLE;
}

uint32_t
config_get_val_log_facility(void)
{
	return (3<<3); /* LOG_DAEMON */
}

enum incidence_action
incidence_get_action(enum incidence_id id)
{
	return INAC_ERROR;
}

void
config_set_rsync_priority(unsigned int value)
{
	rsync_priority = value;
}

void
config_set_http_priority(unsigned int value)
{
	http_priority = value;
}

unsigned int
config_get_thread_pool_validation_max(void)
{
	return 10;
}

unsigned int
config_get_max_asn_per_pfx(void)
{
	return 10;
}

unsigned int
config_get_max_pfx_per_asn(void)
{
	return 10;
}

