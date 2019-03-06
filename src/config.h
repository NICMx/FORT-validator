#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <toml.h>
#include <openssl/bio.h>

/**
 * Note: The only repository synchronization protocol implemented so far is
 * RSYNC. Whenever you see "sync", think "rsync."
 */
enum sync_strategy {
	/**
	 * Synchronization is turned off.
	 * The validator will work on an already downloaded repository.
	 */
	SYNC_OFF,
	/**
	 * Strictly correct download strategy.
	 *
	 * The validator will sync each repository publication point separately
	 * as requested by each caRepository contained in the CA certificates'
	 * SIA extensions.
	 *
	 * No risk of downloading unneeded files, but otherwise slow, as every
	 * different repository publication point requires a separate sync call.
	 */
	SYNC_STRICT,
	/**
	 * Always download the likely root of the entire repository.
	 *
	 * For example, if we get the following caRepositories:
	 *
	 * - `rsync://a.b.c/d/e/f/g/h/i`
	 * - `rsync://a.b.c/d/e/f/g/h/j`
	 * - `rsync://a.b.c/d/e/f/k`
	 *
	 * This strategy will synchronize `rsync://a.b.c/d` while parsing the
	 * first caRepository, and then skip synchronization during the second
	 * and third ones. (Because they are already downloaded.)
	 *
	 * This strategy risks downloading unneeded files, and even failing due
	 * to lack of read permissions on stray subdirectories. On the flip
	 * side, if the repository holds no unnecessary subdirectories, then
	 * this strategy is the fastest one, since it generally only requires
	 * one sync call per domain, which often translates into one sync call
	 * per validation cycle.
	 *
	 * Currently, all of the official repositories are actually specifically
	 * structured to benefit this strategy.
	 */
	SYNC_ROOT,
};

#define SYNC_VALUE_OFF		"off"
#define SYNC_VALUE_STRICT	"strict"
#define SYNC_VALUE_ROOT		"root"

enum filename_format {
	/** Example: "rsync://repository.lacnic.net/rpki/foo/bar/baz.cer" */
	FNF_GLOBAL,
	/** Example: "/tmp/repo/repository.lacnic.net/rpki/foo/bar/baz.cer" */
	FNF_LOCAL,
	/** Example: "baz.cer" */
	FNF_NAME,
};

#define FNF_VALUE_GLOBAL "global-url"
#define FNF_VALUE_LOCAL "local-path"
#define FNF_VALUE_NAME "file-name"

struct rpki_config;

struct group_fields;
struct option_field;

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

struct string_array {
	char **array;
	size_t length;
};

void *get_rpki_config_field(struct option_field const *);
int handle_flags_config(int , char **);

void get_group_fields(struct group_fields const **);

char const *config_get_tal(void);
char const *config_get_local_repository(void);
enum sync_strategy config_get_sync_strategy(void);
bool config_get_shuffle_uris(void);
unsigned int config_get_max_cert_depth(void);
bool config_get_color_output(void);
enum filename_format config_get_filename_format(void);
FILE *config_get_roa_output(void);
char *config_get_rsync_program(void);
struct string_array const *config_get_rsync_args(void);

void free_rpki_config(void);

#endif /* SRC_CONFIG_H_ */
