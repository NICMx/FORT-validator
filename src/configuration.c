#include "configuration.h"

#include <sys/socket.h>
#include <err.h>
#include <errno.h>
#include <jansson.h>
#include <stdbool.h>
#include <string.h>

#include "common.h"
#include "csv.h"

#define OPTNAME_LISTEN		"listen"
#define OPTNAME_LISTEN_ADDRESS	"address"
#define OPTNAME_LISTEN_PORT	"port"
#define OPTNAME_VRPS	"vrps"

#define DEFAULT_ADDR		NULL
#define DEFAULT_PORT		"323"
#define DEFAULT_VRPS		NULL

struct rtr_config {
	/** The listener address of the RTR server. */
	struct addrinfo *address;
	/** Stored aside only for printing purposes. */
	char *port;
	/** VRPs (Validated ROA Payload) location */
	char *vrps;
} config;

static int handle_json(json_t *);
static int json_get_string(json_t *, char const *, char *, char const **);
static int init_addrinfo(char const *, char const *);
static int init_vrps_db(char const *);

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
	if (config.vrps != NULL)
		free(config.vrps);
}

static int
handle_json(json_t *root)
{
	json_t *listen;
	char const *address;
	char const *port;
	char const *vrps;
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

	} else {
		address = DEFAULT_ADDR;
		port = DEFAULT_PORT;
	}

	error = json_get_string(root, OPTNAME_VRPS,
			    DEFAULT_VRPS, &vrps);
	if (error)
		return error;

	error = init_vrps_db(vrps);
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
init_vrps_db(char const *vrps_location)
{
	/* FIXME Complete me! */
	int error;

	if (vrps_location == NULL || strlen(vrps_location) < 1) {
		warnx("VRPs location must be set");
		return -EINVAL;
	}

	error = parse_file(vrps_location);
	if (error)
		return error; /* Error msg already printed. */

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

	config.port = str_clone(service);
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
config_get_vrps(void)
{
	return config.vrps;
}
