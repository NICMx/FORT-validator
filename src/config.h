#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdbool.h>
#include <stddef.h>

struct rpki_config;

struct group_fields;
struct option_field;

typedef void (*print_function)(struct group_fields const *,
    struct option_field const *, void *);
typedef int (*parse_function)(struct option_field const *, char const *,
    void *);
typedef int (*handler_function)(struct option_field const *, char *);

struct global_type {
	/** Same as struct option.has_arg. Mandatory. */
	int has_arg;
	/**
	 * Number of bytes this data type uses in the rpki_config structure.
	 * Optional. Defaults to zero, obviously.
	 */
	size_t size;

	/**
	 * Prints this data type during the print_config() function.
	 * Optional.
	 */
	print_function print;
	/**
	 * Convers from string to this data type.
	 * If the option's handler is not NULL, this is optional.
	 */
	parse_function parse;
	/**
	 * Function that will release this data type.
	 * If the option's handler is not NULL, this is optional.
	 */
	void (*free)(void *);

	/**
	 * Descriptor of this type's payload. Printed in usage documentation.
	 * For example, in `--tal=<file>`, @arg_doc is "<file>".
	 * The type might have no payload, so this is optional.
	 */
	char const *arg_doc;
};

/** This option can be set from the command line. */
#define AVAILABILITY_GETOPT (1 << 0)
/** This option can be set from the TOML file. */
#define AVAILABILITY_TOML (1 << 1)

struct option_field {
	/*
	 * Must be zero, alphanumeric or >= 1000.
	 * If zero, signals the end of the array.
	 * If alphanumeric, it's the short option name character.
	 * Otherwise it's just a non-printable identifier.
	 * Must be unique across all option fields.
	 * Mandatory.
	 */
	int id;
	/**
	 * For example, if the option name is '--potato', then @name is
	 * "potato".
	 * Mandatory.
	 */
	char const *name;

	/** Data type. Mandatory. */
	struct global_type const *type;
	/**
	 * Number of bytes between the beginning of the struct rpki_config
	 * and the position where this option is stored.
	 * Only relevant when @handler == NULL.
	 */
	size_t offset;
	/** Overrides @type->parser and @offset. Optional. */
	handler_function handler;

	/**
	 * Explanation of the field, for user consumption.
	 * Mandatory.
	 */
	const char *doc;
	/** Overrides type->arg_doc. Optional. */
	char const *arg_doc;
	/**
	 * AVAILABILITY_* flags above.
	 * Default availability is everywhere.
	 * Optional.
	 */
	int availability;
	unsigned int min;
	unsigned int max;
};

struct group_fields {
	char const *name;
	struct option_field const *options;
};

int parse_option(struct option_field const *, char const *);
int handle_flags_config(int , char **);

void get_group_fields(struct group_fields const **);

char const *config_get_tal(void);
char const *config_get_local_repository(void);
bool config_get_enable_rsync(void);
bool config_get_shuffle_uris(void);
unsigned int config_get_max_cert_depth(void);
bool config_get_color_output(void);
void free_rpki_config(void);

#endif /* SRC_CONFIG_H_ */
