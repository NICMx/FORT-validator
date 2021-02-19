#ifndef SRC_DAEMON_H_
#define SRC_DAEMON_H_

typedef void (*daemon_log_cb)(void);
int daemonize(daemon_log_cb);

#endif /* SRC_DAEMON_H_ */
