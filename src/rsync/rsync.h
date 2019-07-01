#ifndef SRC_RSYNC_RSYNC_H_
#define SRC_RSYNC_RSYNC_H_

#include <stdbool.h>
#include "uri.h"

int download_files(struct rpki_uri *, bool, bool);
int rsync_init(void);
void rsync_destroy(void);


#endif /* SRC_RSYNC_RSYNC_H_ */
