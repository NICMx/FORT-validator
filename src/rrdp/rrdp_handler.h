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
	/* Get the data related to an URI */
	int (*uri_get_serial)(char const *, unsigned long *);
};

enum rrdp_uri_cmp_result rhandler_uri_cmp(char const *, char const *, unsigned long);
int rhandler_uri_update(char const *, char const *, unsigned long);
int rhandler_uri_get_serial(char const *, unsigned long *);

#endif /* SRC_RRDP_RRDP_HANDLER_H_ */
