#ifndef SRC_OBJECT_CERTIFICATE_H_
#define SRC_OBJECT_CERTIFICATE_H_

#include <stdbool.h>
#include "state.h"

bool is_certificate(char const *);
X509 *certificate_load(struct validation *, const char *);
int certificate_handle(struct validation *, char const *);
int certificate_handle_extensions(struct validation *, X509 *);

#endif /* SRC_OBJECT_CERTIFICATE_H_ */
