#ifndef SRC_RRDP_RRDP_HANDLER_H_
#define SRC_RRDP_RRDP_HANDLER_H_

#include "rrdp/rrdp_objects.h"

/*
 * Almost the same idea as 'validation_handler.h', only that the main focus is
 * a multithreaded environment.
 *
 * The RRDP URIs are expected to live at the main thread, the other threads can
 * access such URIs. The handler must assure that the data is safe
 * (handle r/w locks), that's the reason why there isn't any reference to a
 * 'db_rrdp' struct.
 */

struct rrdp_handler {
	/*
	 * Search the RRDP URI, returns the corresponding enum to indicate
	 * the comparison result.
	 */
	enum rrdp_uri_cmp_result (*uri_cmp)(char const *, char const *,
	    unsigned long);
	/* Add or update an RRDP URI */
	int (*uri_update)(char const *, char const *, unsigned long);
	/*
	 * Get the serial related to an URI, returns -ENOENT if the URI doesn't
	 * exists, any other error means that something went wrong.
	 */
	int (*uri_get_serial)(char const *, unsigned long *);
	/*
	 * Get the last update that an URI was requested, returns -ENOENT if
	 * the URI doesn't exists, any other error means that something went
	 * wrong.
	 */
	int (*uri_get_last_update)(char const *, long *);
	/* Set the last update to now */
	int (*uri_set_last_update)(char const *);
};

enum rrdp_uri_cmp_result rhandler_uri_cmp(char const *, char const *, unsigned long);
int rhandler_uri_update(char const *, char const *, unsigned long);
int rhandler_uri_get_serial(char const *, unsigned long *);
int rhandler_uri_get_last_update(char const *, long *);
int rhandler_uri_set_last_update(char const *);

#endif /* SRC_RRDP_RRDP_HANDLER_H_ */
