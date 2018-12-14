#include "configuration.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <regex.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <jansson.h>

#include "common.h"
#include "file.h"

#define OPTNAME_LISTEN			"listen"
#define OPTNAME_LISTEN_SERVER	"server_name"
#define OPTNAME_LISTEN_PORT		"server_port"

static int json_to_config(json_t *, struct rtr_config *);
static int handle_listen_config(json_t *, struct rtr_config *);
static json_t *load_json(const char *);

void
free_rtr_config(struct rtr_config *config)
{
	if (!config)
		return;

	if (config->host_address)
		freeaddrinfo(config->host_address);

	free(config);
}

static bool
endsWith(char *string, char *suffix)
{
	size_t strilen;
	size_t suflen;
	if (!string || !suffix)
		return false;

	strilen = strlen(string);
	suflen = strlen(suffix);

	return ((strilen >= suflen) && (0 == strcmp(string + strilen - suflen, suffix)));
}

int
read_config_from_file(char *json_file_path, struct rtr_config **result)
{
	int error;
	int is_json_file;
	json_t *root_json;
	struct rtr_config *config;
	struct file_contents fc;

	is_json_file = endsWith(json_file_path, ".json");
	if (!is_json_file) {
		log_err("Invalid Json file extension for file '%s'", json_file_path);
		return -EINVAL;
	}

	*result = NULL;
	error = file_load(json_file_path, &fc);
	if (error)
		return error;

	root_json = load_json(fc.buffer);
	file_free(&fc);
	if (!root_json)
		return -ENOENT;

	config = malloc(sizeof(struct rtr_config));
	if (!config)
		return -ENOMEM;

	error = json_to_config(root_json, config);
	if (error)
		free(config);

	*result = config;
	json_decref(root_json);
	return error;
}

static void
check_duplicates(bool *found, char *section)
{
	if (*found)
		log_err("Note: I found multiple '%s' sections.", section);
	*found = true;
}

static int
json_to_config(json_t *json, struct rtr_config *config)
{
	bool listen_found = false;
	int error = 0;
	const char *key;
	json_t *value;

	if (!json || json->type != JSON_OBJECT) {
		log_err0("Invalid JSON config.");
		return -EINVAL;
	}

	json_object_foreach(json, key, value) {
		if(strcasecmp(OPTNAME_LISTEN, key) == 0) {
			check_duplicates(&listen_found, OPTNAME_LISTEN);
			error = handle_listen_config(value, config);
		}
	}

	return error;
}

static int
hostname_to_ip(const char *hostname, struct addrinfo **result)
{
	int rv;
	struct addrinfo hints, *servinfo;

	memset(&hints, 0 , sizeof hints);
	hints.ai_family = AF_UNSPEC;
//	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags |= AI_CANONNAME;


	if ((rv = getaddrinfo(hostname, NULL, &hints, &servinfo)) != 0){
		printf("getaddrinfo: [%d] - %s\n", rv, gai_strerror(rv)); // TODO change to print error or something like that
		return -EINVAL;
	}

	*result = servinfo;

	return 0;
}

static int
handle_listen_config(json_t *json, struct rtr_config *config)
{
	int error;
	bool listen_servername_found = false;
	bool listen_port_found = false;
	const char *key;
	json_t *value;

	if (!json || json->type != JSON_OBJECT) {
		log_err0("Invalid JSON config.");
		return -EINVAL;
	}

	json_object_foreach(json, key, value) {
		if (strcasecmp(OPTNAME_LISTEN_SERVER, key) == 0) {
			check_duplicates(&listen_servername_found, OPTNAME_LISTEN_SERVER);
			if (json_typeof(value) != JSON_STRING) {
				log_err("Invalid value for key '%s'", key);
				return -EINVAL;
			}

			error = hostname_to_ip(json_string_value(value), &config->host_address);
			if (error)
				return error;

		} else if (strcasecmp(OPTNAME_LISTEN_PORT, key) == 0) {
			check_duplicates(&listen_port_found, OPTNAME_LISTEN_PORT);
			if (json_typeof(value) != JSON_INTEGER) {
				log_err("Invalid value for key '%s'", key);
				return -EINVAL;
			}

			config->host_port = (__u16) json_integer_value(value);
		}
	}

	return 0;
}


/*
 * Parse text into a JSON object. If text is valid JSON, returns a
 * json_t structure, otherwise prints and error and returns null.
 */
static json_t *load_json(const char *text) {
    json_t *root;
    json_error_t error;

    root = json_loads(text, 0, &error);

    if (root)
        return root;
    else {
    	log_err("json error on line %d column %d: %s\n", error.line, error.column, error.text);
        return (json_t *)0;
    }
}

