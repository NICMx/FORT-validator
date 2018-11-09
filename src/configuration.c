#include "configuration.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <regex.h>
#include <jansson.h>

#include "common.h"
#include "file.h"
#include "str_utils.h"

#define OPTNAME_LISTEN			"listen"
#define OPTNAME_LISTEN_IPV4		"ipv4_server_addr"

static int json_to_config(json_t *, struct rtr_config *);
static int handle_listen_config(json_t *, struct ipv4_transport_addr *);
static json_t *load_json(const char *);


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

	config = malloc(sizeof(*config));
	if (!config)
		return -ENOMEM;

	error = json_to_config(root_json, config);
	if (error != 0)
		free(config);

	*result = config;
	json_decref(root_json);
	return error;
}

static void
check_duplicates(bool *found, char *section)
{
	if (*found)
		log_info("Note: I found multiple '%s' sections.", section);
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
			error = handle_listen_config(value, &config->ipv4_server_addr);
		}
	}

	return error;
}


static int
handle_listen_config(json_t *json, struct ipv4_transport_addr *ipv4_server_addr)
{
	bool listen_ipv4_found = false;
	const char *key;
	json_t *value;

	if (!json || json->type != JSON_OBJECT) {
		log_err0("Invalid JSON config.");
		return -EINVAL;
	}

	json_object_foreach(json, key, value) {
		if (strcasecmp(OPTNAME_LISTEN_IPV4, key) == 0) {
			check_duplicates(&listen_ipv4_found, OPTNAME_LISTEN_IPV4);
			if (json_typeof(value) != JSON_STRING) {
				log_err("Invalid value for key '%s'", key);
				return -EINVAL;
			}

			str_to_addr4_port(json_string_value(value), ipv4_server_addr);
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

