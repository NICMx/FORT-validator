#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdbool.h>
#include <stddef.h>

struct rpki_config;

struct option_field;

typedef enum global_type_id {
	GTI_BOOL,
	GTI_STRING,
	GTI_U_INT,
} global_type_id;

typedef void (*print_function)(void *, bool);
typedef int (*parse_function)(struct option_field *, char *, void *);
/* This function does not need to validate type->size. */
typedef int (*validate_function)(struct option_field *, void *);

struct args_flag {
	struct option_field *field;
	bool is_set;
};

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

struct group_fields {
	char *group_name;
	struct option_field *options;
	unsigned int options_len;
};

void print_usage(char *progname);
int handle_option(struct rpki_config *, struct option_field *, char *);
int handle_flags_config(int , char **);

void get_group_fields(struct group_fields **);

void config_set(struct rpki_config *);

char const *config_get_tal(void);
char const *config_get_local_repository(void);
bool config_get_enable_rsync(void);
bool config_get_shuffle_uris(void);
unsigned int config_get_max_cert_depth(void);
void free_rpki_config(void);

#endif /* SRC_CONFIG_H_ */
