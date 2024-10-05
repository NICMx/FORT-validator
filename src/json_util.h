#ifndef SRC_JSON_UTIL_H_
#define SRC_JSON_UTIL_H_

#include <arpa/inet.h>
#include <jansson.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Contract of get functions:
 *
 * result = 0: Tag parsed successfully, out param populated.
 * result > 0: Tag was nonexistent, outbound param reset (0 or NULL), not logged
 * result < 0: Tag was fatally invalid, outbound param reset, logged
 */

int json_get_int(json_t *, char const *, int *);
int json_get_u32(json_t *, char const *, uint32_t *);
int json_get_ulong(json_t *, char const *, unsigned long *);
int json_get_ts(json_t *, char const *, time_t *);
int json_get_str(json_t *, char const *, char const **);
int json_get_array(json_t *, char const *, json_t **);
int json_get_object(json_t *, char const *, json_t **);

bool json_valid_members_count(json_t *, size_t);

int json_add_int(json_t *, char const *, int);
int json_add_ulong(json_t *, char const *, unsigned long);
int json_add_str(json_t *, char const *, char const *);
int json_add_ts(json_t *, char const *, time_t);

json_t *json_obj_new(void);
json_t *json_array_new(void);
json_t *json_int_new(json_int_t);
json_t *json_str_new(const char *);
json_t *json_strn_new(const char *, size_t);
int json_object_add(json_t *, char const *, json_t *);
int json_array_add(json_t *, json_t *);

#endif /* SRC_JSON_UTIL_H_ */
