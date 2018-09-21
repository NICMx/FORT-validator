#ifndef SRC_SIGNED_DATA_H_
#define SRC_SIGNED_DATA_H_

/* Some wrappers for libcmscodec's SignedData. */

#include <libcmscodec/SignedData.h>

int signed_data_decode(ANY_t *coded, struct SignedData **result);
void signed_data_free(struct SignedData *sdata);

#endif /* SRC_SIGNED_DATA_H_ */
