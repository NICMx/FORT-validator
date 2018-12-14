#ifndef SRC_RSYNC_RSYNC_H_
#define SRC_RSYNC_RSYNC_H_

#include <stdbool.h>

int download_files(const char *);
int rsync_init(bool);
void rsync_destroy();


#endif /* SRC_RSYNC_RSYNC_H_ */
