#ifndef SRC_RRDP_RRDP_H_
#define SRC_RRDP_RRDP_H_

#include "types/uri.h"

/*
 * TODO (aaaa)
 *
   When the Relying Party downloads an Update Notification File, it MUST
   verify the file format and validation steps described in
   Section 3.5.1.3.  If this verification fails, the file MUST be
   rejected and RRDP cannot be used.  See Section 3.4.5 for
   considerations.
 */

int rrdp_update(struct rpki_uri *);

#endif /* SRC_RRDP_RRDP_H_ */
