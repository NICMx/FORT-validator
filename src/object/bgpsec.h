#ifndef SRC_OBJECT_BGPSEC_H_
#define SRC_OBJECT_BGPSEC_H_

#include <openssl/x509.h>
#include "resource.h"
#include "rpp.h"

int handle_bgpsec(X509 *, struct resources *, struct rpp *);

#endif /* SRC_OBJECT_BGPSEC_H_ */
