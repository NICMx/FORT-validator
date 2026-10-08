#ifndef SRC_RSYNC_RSYNC_H_
#define SRC_RSYNC_RSYNC_H_

#include "types/uri.h"

void rsync_setup(void);
int rsync_queue(struct uri const *, char const *, bool);
void rsync_finished(struct uri const *, char const *);
void rsync_teardown(void);

#endif /* SRC_RSYNC_RSYNC_H_ */
