#ifndef VALIDATOR_OBJECT_BGPSEC_H_
#define VALIDATOR_OBJECT_BGPSEC_H_

#include "validator/resource.h"
#include "validator/types/rpp.h"

int handle_bgpsec(X509 *, struct resources *, struct rpp *);

#endif /* VALIDATOR_OBJECT_BGPSEC_H_ */
