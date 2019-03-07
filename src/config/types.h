#ifndef SRC_CONFIG_TYPES_H_
#define SRC_CONFIG_TYPES_H_

#include <stdint.h>
#include <stdio.h>
#include <toml.h>

struct option_field;
struct group_fields;

/** This option can be set from the command line. */
#define AVAILABILITY_GETOPT (1 << 0)
/** This option can be set from the TOML file. */
#define AVAILABILITY_TOML (1 << 1)

typedef void (*print_function)(
    struct group_fields const *,
    struct option_field const *,
    void *
);
typedef int (*argv_parse_function)(
    struct option_field const *,
    char const *,
    void *
);
typedef int (*toml_parse_function)(
    struct option_field const *,
    struct toml_table_t *,
    void *
);
typedef int (*handler_function)(
    struct option_field const *,
    char *
);

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
	 * Explanation of the field, for user consumption during --help.
	 * Meant to be short; the bulk of it should be found in the manpage.
	 * Probably should not include punctuation at the end.
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

	/** If the option's handler is not NULL, this is optional. */
	struct {
		/**
		 * Convers from string to this data type.
		 * Optional if there are no fields of this type that are read
		 * from argv.
		 */
		argv_parse_function argv;
		/**
		 * Converts from a TOML node to this data type.
		 * Optional if there are no fields of this type that are read
		 * from TOML files.
		 */
		toml_parse_function toml;
	} parse;

	/**
	 * Function that will release this data type.
	 * If the option's handler is not NULL, this is optional.
	 *
	 * IMPORTANT: This function might be called twice in succession.
	 * Therefore, make sure that it nullifies the value, and reacts properly
	 * when the input is NULL.
	 */
	void (*free)(void *);

	/**
	 * Descriptor of this type's payload. Printed in usage documentation.
	 * For example, in `--tal=<file>`, @arg_doc is "<file>".
	 * The type might have no payload, so this is optional.
	 */
	char const *arg_doc;
};

#endif /* SRC_CONFIG_TYPES_H_ */
