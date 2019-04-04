#include "configuration.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <err.h>
#include <errno.h>
#include <jansson.h>
#include <stdbool.h>
#include <string.h>

#include "common.h"
#include "csv.h"

#define OPTNAME_LISTEN			"listen"
#define OPTNAME_LISTEN_ADDRESS		"address"
#define OPTNAME_LISTEN_PORT		"port"
#define OPTNAME_LISTEN_QUEUE		"queue"
#define OPTNAME_VRPS			"vrps"
#define OPTNAME_VRPS_LOCATION		"location"
#define OPTNAME_VRPS_CHECK_INTERVAL	"checkInterval"
#define OPTNAME_RTR_INTERVAL		"rtrInterval"
#define OPTNAME_RTR_INTERVAL_REFRESH	"refresh"
#define OPTNAME_RTR_INTERVAL_RETRY	"retry"
#define OPTNAME_RTR_INTERVAL_EXPIRE	"expire"
#define OPTNAME_SLURM			"slurm"
#define OPTNAME_SLURM_LOCATION		"location"
#define OPTNAME_SLURM_CHECK_INTERVAL	"checkInterval"

#define DEFAULT_ADDR			NULL
#define DEFAULT_PORT			"323"
#define DEFAULT_QUEUE			10
#define DEFAULT_VRPS_LOCATION		NULL
#define DEFAULT_VRPS_CHECK_INTERVAL	60
#define DEFAULT_REFRESH_INTERVAL	3600
#define DEFAULT_RETRY_INTERVAL		600
#define DEFAULT_EXPIRE_INTERVAL		7200
#define DEFAULT_SLURM_LOCATION		NULL
#define DEFAULT_SLURM_CHECK_INTERVAL	60

/* Protocol timing parameters ranges in secs */
#define MIN_VRPS_CHECK_INTERVAL		60
#define MAX_VRPS_CHECK_INTERVAL		7200
#define MIN_REFRESH_INTERVAL		1
#define MAX_REFRESH_INTERVAL		86400
#define MIN_RETRY_INTERVAL		1
#define MAX_RETRY_INTERVAL		7200
#define MIN_EXPIRE_INTERVAL		600
#define MAX_EXPIRE_INTERVAL		172800
#define MIN_SLURM_CHECK_INTERVAL	60
#define MAX_SLURM_CHECK_INTERVAL	7200

/* Range values for other params */
#define MIN_LISTEN_QUEUE		1
#define MAX_LISTEN_QUEUE		SOMAXCONN

struct rtr_config {
	/** The listener address of the RTR server. */
	struct addrinfo *address;
	/** Stored aside only for printing purposes. */
	char *port;
	/** Maximum accepted client connections */
	int queue;
	/** VRPs (Validated ROA Payload) location */
	char *vrps_location;
	/** Interval used to look for updates at VRPs location */
	int vrps_check_interval;
	/** Intervals use at RTR v1 End of data PDU **/
	int refresh_interval;
	int retry_interval;
	int expire_interval;
	/** SLURM location */
	char *slurm_location;
	/** Interval used to look for updates at SLURM location */
	int slurm_check_interval;
} config;

static int handle_json(json_t *);
static int json_get_string(json_t *, char const *, char *, char const **);
static int json_get_int(json_t *, char const *, int, int *);
static int init_addrinfo(char const *, char const *);

int
config_init(char const *json_file_path)
{
	json_t *json_root;
	json_error_t json_error;
	int error;

	if (json_file_path == NULL)
		return -EINVAL;

	json_root = json_load_file(json_file_path, JSON_REJECT_DUPLICATES,
	    &json_error);
	if (json_root == NULL) {
		warnx("JSON error on line %d, column %d: %s",
		    json_error.line, json_error.column, json_error.text);
		return -ENOENT;
	}

	error = handle_json(json_root);

	json_decref(json_root);
	return error;
}

void
config_cleanup(void)
{
	if (config.address != NULL)
		freeaddrinfo(config.address);
	if (config.port != NULL)
		free(config.port);
	if (config.vrps_location != NULL)
		free(config.vrps_location);
}

static int
load_range(json_t *parent, char const *name, int default_value,
    int *result, int min_value, int max_value)
{
	int error;

	error = json_get_int(parent, name, default_value, result);
	if (error) {
		warnx("Invalid value for '%s'", name);
		return error;
	}

	if (*result < min_value || max_value < *result) {
		warnx("'%s' (%d) out of range, must be from %d to %d", name,
		    *result, min_value, max_value);
		return -EINVAL;
	}

	return 0;
}

static int
load_vrps(json_t *root)
{
	struct stat attr;
	json_t *vrps;
	char const *vrps_location;
	int vrps_check_interval;
	int error;

	vrps = json_object_get(root, OPTNAME_VRPS);
	if (vrps != NULL) {
		if (!json_is_object(vrps)) {
			warnx("The '%s' element is not a JSON object.",
			    OPTNAME_VRPS);
			return -EINVAL;
		}

		error = json_get_string(vrps, OPTNAME_VRPS_LOCATION,
			    DEFAULT_VRPS_LOCATION, &vrps_location);
		if (error)
			return error;

		config.vrps_location = strdup(vrps_location);
		if (config.vrps_location == NULL) {
			warn("'%s' couldn't be allocated.",
			    OPTNAME_VRPS_LOCATION);
			return -errno;
		}

		/*
		 * RFC 6810 and 8210:
		 * The cache MUST rate-limit Serial Notifies to no more frequently than
		 * one per minute.
		 */
		error = load_range(vrps, OPTNAME_VRPS_CHECK_INTERVAL,
		    DEFAULT_VRPS_CHECK_INTERVAL, &vrps_check_interval,
		    MIN_VRPS_CHECK_INTERVAL, MAX_VRPS_CHECK_INTERVAL);
		if (error)
			return error;
		config.vrps_check_interval = vrps_check_interval;
	} else {
		config.vrps_location = DEFAULT_VRPS_LOCATION;
		config.vrps_check_interval = DEFAULT_VRPS_CHECK_INTERVAL;
	}

	/* Validate required data */
	error = stat(config.vrps_location, &attr) < 0;
	if (error) {
		warn("VRPs location '%s' isn't a valid path",
		    config.vrps_location);
		return -errno;
	}
	if (S_ISDIR(attr.st_mode) != 0) {
		warnx("VRPs location '%s' isn't a file", config.vrps_location);
		return -EINVAL;
	}

	return 0;
}

/*
 * Exclusively for RTR v1, so this are optional values to configure
 * since RTR v1 isn't fully supported yet
 */
static int
load_intervals(json_t *root)
{
	json_t *interval;
	int refresh_interval;
	int retry_interval;
	int expire_interval;
	int error;
	interval = json_object_get(root, OPTNAME_RTR_INTERVAL);
	if (interval != NULL) {
		if (!json_is_object(interval)) {
			warnx("The '%s' element is not a JSON object.",
			    OPTNAME_RTR_INTERVAL);
			return -EINVAL;
		}

		error = load_range(interval, OPTNAME_RTR_INTERVAL_REFRESH,
		    DEFAULT_REFRESH_INTERVAL, &refresh_interval,
		    MIN_REFRESH_INTERVAL, MAX_REFRESH_INTERVAL);
		if (error)
			return error;

		error = load_range(interval, OPTNAME_RTR_INTERVAL_RETRY,
		    DEFAULT_RETRY_INTERVAL, &retry_interval,
		    MIN_RETRY_INTERVAL, MAX_RETRY_INTERVAL);
		if (error)
			return error;

		error = load_range(interval, OPTNAME_RTR_INTERVAL_EXPIRE,
		    DEFAULT_EXPIRE_INTERVAL, &expire_interval,
		    MIN_EXPIRE_INTERVAL, MAX_EXPIRE_INTERVAL);
		if (error)
			return error;

		config.refresh_interval = refresh_interval;
		config.retry_interval = retry_interval;
		config.expire_interval = expire_interval;
	} else {
		config.refresh_interval = DEFAULT_REFRESH_INTERVAL;
		config.retry_interval = DEFAULT_RETRY_INTERVAL;
		config.expire_interval = DEFAULT_EXPIRE_INTERVAL;
	}

	return 0;
}

static int
load_slurm(json_t *root)
{
	struct stat attr;
	json_t *slurm;
	char const *slurm_location;
	int slurm_check_interval;
	int error;

	slurm = json_object_get(root, OPTNAME_SLURM);
	if (slurm != NULL) {
		if (!json_is_object(slurm)) {
			warnx("The '%s' element is not a JSON object.",
			    OPTNAME_VRPS);
			return -EINVAL;
		}

		error = json_get_string(slurm, OPTNAME_SLURM_LOCATION,
			    DEFAULT_SLURM_LOCATION, &slurm_location);
		if (error)
			return error;

		config.slurm_location = strdup(slurm_location);
		if (config.slurm_location == NULL) {
			warn("'%s' couldn't be allocated.",
			    OPTNAME_SLURM_LOCATION);
			return -errno;
		}

		error = load_range(slurm, OPTNAME_SLURM_CHECK_INTERVAL,
		    DEFAULT_SLURM_CHECK_INTERVAL, &slurm_check_interval,
		    MIN_SLURM_CHECK_INTERVAL, MAX_SLURM_CHECK_INTERVAL);
		if (error)
			return error;
		config.slurm_check_interval = slurm_check_interval;
	} else {
		config.slurm_location = DEFAULT_SLURM_LOCATION;
		config.slurm_check_interval = DEFAULT_SLURM_CHECK_INTERVAL;
	}

	/* Validate data (only if a value was set */
	if (config.slurm_location == NULL)
		return 0;

	error = stat(config.slurm_location, &attr) < 0;
	if (error) {
		warn("SLURM location '%s' isn't a valid path",
		    config.slurm_location);
		return -errno;
	}
	if (S_ISDIR(attr.st_mode) != 0) {
		warnx("SLURM location '%s' isn't a file",
		    config.slurm_location);
		return -EINVAL;
	}

	return 0;
}

static int
handle_json(json_t *root)
{
	json_t *listen;
	char const *address;
	char const *port;
	int queue;
	int error;

	if (!json_is_object(root)) {
		warnx("The root of the JSON file is not a JSON object.");
		return -EINVAL;
	}

	listen = json_object_get(root, OPTNAME_LISTEN);
	if (listen != NULL) {
		if (!json_is_object(listen)) {
			warnx("The '%s' element is not a JSON object.",
			    OPTNAME_LISTEN);
			return -EINVAL;
		}

		error = json_get_string(listen, OPTNAME_LISTEN_ADDRESS,
		    DEFAULT_ADDR, &address);
		if (error)
			return error;

		error = json_get_string(listen, OPTNAME_LISTEN_PORT,
		    DEFAULT_PORT, &port);
		if (error)
			return error;

		error = load_range(listen, OPTNAME_LISTEN_QUEUE,
		    DEFAULT_QUEUE, &queue,
		    MIN_LISTEN_QUEUE, MAX_LISTEN_QUEUE);
		if (error)
			return error;
		config.queue = queue;

	} else {
		address = DEFAULT_ADDR;
		port = DEFAULT_PORT;
		config.queue = DEFAULT_QUEUE;
	}

	error = load_vrps(root);
	if (error)
		return error;

	error = load_intervals(root);
	if (error)
		return error;

	error = load_slurm(root);
	if (error)
		return error;

	return init_addrinfo(address, port);
}

static int
json_get_string(json_t *parent, char const *name, char *default_value,
    char const **result)
{
	json_t *child;

	child = json_object_get(parent, name);
	if (child == NULL) {
		*result = default_value;
		return 0;
	}

	if (!json_is_string(child)) {
		warnx("The '%s' element is not a JSON string.", name);
		return -EINVAL;
	}

	*result = json_string_value(child);
	return 0;
}

static int
json_get_int(json_t *parent, char const *name, int default_value,
    int *result)
{
	json_t *child;

	child = json_object_get(parent, name);
	if (child == NULL) {
		*result = default_value;
		return 0;
	}

	if (!json_is_integer(child)) {
		warnx("The '%s' element is not a JSON integer.", name);
		return -EINVAL;
	}

	*result = json_integer_value(child);
	return 0;
}

static int
init_addrinfo(char const *hostname, char const *service)
{
	int error;
	struct addrinfo hints;

	memset(&hints, 0 , sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	/* hints.ai_socktype = SOCK_DGRAM; */
	hints.ai_flags |= AI_PASSIVE;

	error = getaddrinfo(hostname, service, &hints, &config.address);
	if (error) {
		warnx("Could not infer a bindable address out of address '%s' and port '%s': %s",
		    (hostname != NULL) ? hostname : "any", service,
		    gai_strerror(error));
		return -error;
	}

	config.port = strdup(service);
	if (config.port == NULL) {
		warn( "'%s' couldn't be allocated.", OPTNAME_LISTEN_PORT);
		return -errno;
	}

	return 0;
}

struct addrinfo const *
config_get_server_addrinfo(void)
{
	return config.address;
}

char const *
config_get_server_port(void)
{
	return config.port;
}

int
config_get_server_queue(void)
{
	return config.queue;
}

char const *
config_get_vrps_location(void)
{
	return config.vrps_location;
}

int
config_get_vrps_check_interval(void)
{
	return config.vrps_check_interval;
}

int
config_get_refresh_interval(void)
{
	return config.refresh_interval;
}

int
config_get_retry_interval(void)
{
	return config.retry_interval;
}

int
config_get_expire_interval(void)
{
	return config.expire_interval;
}

char const *
config_get_slurm_location(void)
{
	return config.slurm_location;
}

int
config_get_slurm_check_interval(void)
{
	return config.slurm_check_interval;
}
