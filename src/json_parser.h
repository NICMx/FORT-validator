#ifndef SRC_JSON_PARSER_H_
#define SRC_JSON_PARSER_H_

#include <jansson.h>

int json_get_string(json_t *, char const *, char const **);
int json_get_int(json_t *, char const *, json_int_t *);
json_t *json_get_array(json_t *, char const *);
json_t *json_get_object(json_t *, char const *);

#endif /* SRC_JSON_PARSER_H_ */
