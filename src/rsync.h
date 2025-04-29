#ifndef SRC_RSYNC_RSYNC_H_
#define SRC_RSYNC_RSYNC_H_

#include "types/url.h"

void rsync_setup(char const *, ...);
int rsync_queue(struct uri const *, char const *);
void rsync_finished(struct uri const *, char const *);
void rsync_teardown(void);

#endif /* SRC_RSYNC_RSYNC_H_ */
