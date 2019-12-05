#ifndef SRC_DELETE_DIR_DAEMON_H_
#define SRC_DELETE_DIR_DAEMON_H_

#include <pthread.h>

int delete_dir_daemon_start(pthread_t *, char const *);
void delete_dir_daemon_destroy(pthread_t);

#endif /* SRC_DELETE_DIR_DAEMON_H_ */
