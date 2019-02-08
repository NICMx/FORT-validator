#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdbool.h>
#include <stddef.h>

struct rpki_config {
	/* tal file path*/
	char *tal;
	/* Local repository path */
	char *local_repository;
	/* Disable rsync downloads */
	bool enable_rsync;
	/* Shuffle uris in tal */
	bool shuffle_uris;
	/* Configuration file path */
	bool flag_config;
};

typedef enum global_type_id {
	GTI_BOOL,
	GTI_STRING,
} global_type_id;

struct option_field;

typedef void (*print_function)(void *, bool);
typedef int (*parse_function)(struct option_field *, char *, void *);
/* This function does not need to validate type->size. */
typedef int (*validate_function)(struct option_field *, void *);

struct global_type {
	global_type_id id;
	const char *name;
	size_t size;
	print_function print;
	parse_function parse;
	validate_function validate;
	char *candidates;
};

struct option_field {
	char *name; /* This being NULL means the end of the array. */
	struct global_type *type;
	const char *doc;
	size_t offset;
	int has_arg;
	char short_opt;
	unsigned long min;
	unsigned long max;
	print_function print; /* Overrides type->print. */
	validate_function validate; /* Overrides type->validate. */
	char *candidates; /* Overrides type->candidates. */
	bool required;
};

int handle_option(struct rpki_config *, struct option_field *, char *);
int handle_flags_config(int , char **, struct rpki_config *);

void get_global_fields(struct option_field **, unsigned int *);

void get_tal_fields(struct option_field **, unsigned int *);

#endif /* SRC_CONFIG_H_ */
