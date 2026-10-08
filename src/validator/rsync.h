#ifndef VALIDATOR_RSYNC_H_
#define VALIDATOR_RSYNC_H_

#include "common/types/uri.h"

void rsync_setup(void);
int rsync_queue(struct uri const *, char const *, bool);
void rsync_finished(struct uri const *, char const *);
void rsync_teardown(void);

#endif /* VALIDATOR_RSYNC_H_ */
