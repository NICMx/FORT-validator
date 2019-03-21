#include "configuration.h"

#include <sys/socket.h>
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

#define DEFAULT_ADDR			NULL
#define DEFAULT_PORT			"323"
#define DEFAULT_QUEUE			10
#define DEFAULT_VRPS_LOCATION		NULL
#define DEFAULT_VRPS_CHECK_INTERVAL	60
#define DEFAULT_REFRESH_INTERVAL	3600
#define DEFAULT_RETRY_INTERVAL		600
#define DEFAULT_EXPIRE_INTERVAL		7200

/* Protocol timing parameters ranges in secs */
#define MIN_VRPS_CHECK_INTERVAL		60
#define MAX_VRPS_CHECK_INTERVAL		7200
#define MIN_REFRESH_INTERVAL		1
#define MAX_REFRESH_INTERVAL		86400
#define MIN_RETRY_INTERVAL		1
#define MAX_RETRY_INTERVAL		7200
#define MIN_EXPIRE_INTERVAL		600
#define MAX_EXPIRE_INTERVAL		172800

/* Range values for other params */
#define MIN_LISTEN_QUEUE		1
#define MAX_LISTEN_QUEUE		SOMAXCONN

struct rtr_config {
	/** The listener address of the RTR server. */
	struct addrinfo *address;
	/** Stored aside only for printing purposes. */
	char *port;
	/** VRPs (Validated ROA Payload) location */
	char *vrps_location;
	/** Maximum accepted client connections */
	int queue;
	/** Interval used to look for updates at VRPs location */
	int vrps_check_interval;
	/** Intervals use at RTR v1 End of data PDU **/
	int refresh_interval;
	int retry_interval;
	int expire_interval;
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

	/*
	 * TODO What's the point of a default start if there's
	 * no vrps input?
	 */
	if (json_file_path == NULL)
		return init_addrinfo(DEFAULT_ADDR, DEFAULT_PORT);

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
		err(error, "Invalid value for '%s'", name);
		return error;
	}

	if (*result < min_value || max_value < *result) {
		err(-EINVAL, "'%s' (%d) out of range, must be from %d to %d",
		    name, *result, min_value, max_value);
		return -EINVAL;
	}

	return 0;
}

static int
handle_json(json_t *root)
{
	json_t *listen;
	json_t *vrps;
	json_t *interval;
	char const *address;
	char const *port;
	char const *vrps_location;
	int queue;
	int vrps_check_interval;
	int refresh_interval;
	int retry_interval;
	int expire_interval;
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
			err(errno, "'%s' couldn't be allocated.",
					OPTNAME_VRPS_LOCATION);
			return errno;
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

	/*
	 * Exclusively for RTR v1, so this are optional values to configure
	 * since RTR v1 isn't fully supported yet
	 */
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
		return error;
	}

	/* TODO (review) check NULL */
	config.port = strdup(service);
	if (config.port == NULL) {
		err(errno, "'%s' couldn't be allocated.", OPTNAME_LISTEN_PORT);
		return errno;
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

char const *
config_get_vrps_location(void)
{
	return config.vrps_location;
}

int
config_get_server_queue(void)
{
	return config.queue;
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
