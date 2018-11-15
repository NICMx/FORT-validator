#ifndef SRC_OBJECT_CRL_H_
#define SRC_OBJECT_CRL_H_

#include <stdbool.h>
#include "state.h"

bool is_crl(char const *);
int handle_crl(struct validation *, char const *);

#endif /* SRC_OBJECT_CRL_H_ */
