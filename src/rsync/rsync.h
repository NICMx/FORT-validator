#ifndef SRC_RSYNC_RSYNC_H_
#define SRC_RSYNC_RSYNC_H_

#include <stdbool.h>
#include "types/uri.h"

struct uri_list;

int rsync_download_files(struct rpki_uri *, bool, bool);
struct uri_list *rsync_create(void);
void rsync_destroy(struct uri_list *);

void reset_downloaded(void);

#endif /* SRC_RSYNC_RSYNC_H_ */
