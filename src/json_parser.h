#ifndef SRC_JSON_PARSER_H_
#define SRC_JSON_PARSER_H_

#include <jansson.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

int json_get_string(json_t *, char const *, char const **);
int json_get_int(json_t *, char const *, json_int_t *);
json_t *json_get_array(json_t *, char const *);
json_t *json_get_object(json_t *, char const *);

bool json_valid_members_count(json_t *, size_t);

#endif /* SRC_JSON_PARSER_H_ */
