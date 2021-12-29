#ifndef SRC_RSYNC_RSYNC_H_
#define SRC_RSYNC_RSYNC_H_

#include <stdbool.h>
#include "types/uri.h"

int rsync_download_files(struct rpki_uri *, bool);

#endif /* SRC_RSYNC_RSYNC_H_ */
