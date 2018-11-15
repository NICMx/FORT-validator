#ifndef SRC_SIGNED_DATA_H_
#define SRC_SIGNED_DATA_H_

/* Some wrappers for libcmscodec's SignedData. */

#include <libcmscodec/SignedData.h>
#include "state.h"

int signed_data_decode(struct validation *, ANY_t *, struct SignedData **);
void signed_data_free(struct SignedData *);

int get_content_type_attr(struct validation *, struct SignedData *,
    OBJECT_IDENTIFIER_t **);

#endif /* SRC_SIGNED_DATA_H_ */
