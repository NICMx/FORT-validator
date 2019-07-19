#ifndef SRC_OBJECT_BGPSEC_H_
#define SRC_OBJECT_BGPSEC_H_

#include <openssl/x509.h>
#include "resource.h"

int handle_bgpsec(X509 *, unsigned char const *, struct resources *);

#endif /* SRC_OBJECT_BGPSEC_H_ */
