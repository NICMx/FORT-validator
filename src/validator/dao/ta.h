#ifndef SRC_DAO_TA_H_
#define SRC_DAO_TA_H_

#include <stdbool.h>

struct ta_context;

struct ta_context *tactx_create(char const *);
void tactx_free(struct ta_context *);

void tactx_set_refresh(struct ta_context *, char const *);
void tactx_set_unchanged(struct ta_context *);

char const *tactx_map(struct ta_context *, bool);

void tactx_preserve(struct ta_context *, bool);

void tactx_print(struct ta_context *, int);

bool tactx_cleanup(struct ta_context *, char const *);

#endif /* SRC_DAO_TA_H_ */
