#ifndef SRC_RSYNC_RSYNC_H_
#define SRC_RSYNC_RSYNC_H_

void rsync_setup(void);
int rsync_download(char const *, char const *);
unsigned int rsync_finished(void);
void rsync_teardown(void);

#endif /* SRC_RSYNC_RSYNC_H_ */
