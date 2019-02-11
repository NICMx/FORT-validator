#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdbool.h>
#include <stddef.h>

struct rpki_config {
	/* tal file path*/
	char *tal;
	/* Local repository path */
	char *local_repository;
	/* Enable rsync downloads */
	bool enable_rsync;
	/* Shuffle uris in tal */
	bool shuffle_uris;
	/*
	 * rfc6487#section-7.2, last paragraph.
	 * Prevents arbitrarily long paths and loops.
	 */
	unsigned int maximum_certificate_depth;
};

typedef enum global_type_id {
	GTI_BOOL,
	GTI_STRING,
	GTI_U_INT,
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

void config_set(struct rpki_config *);

char const *config_get_tal(void);
char const *config_get_local_repository(void);
bool config_get_enable_rsync(void);
bool config_get_shuffle_uris(void);
unsigned int config_get_max_cert_depth(void);

#endif /* SRC_CONFIG_H_ */
