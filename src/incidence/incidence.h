#ifndef SRC_INCIDENCE_INCIDENCE_H_
#define SRC_INCIDENCE_INCIDENCE_H_

#include <jansson.h>

/*
 * Note: If you need to add, modify or delete an element from this enum,
 * remember that you also need to add it to the incidences array. That's all.
 */
enum incidence_id {
	INID_SIGNATURE_ALGORITHM_HAS_PARAMS,

	__INID_MAX,
};

enum incidence_action {
	/**
	 * Do not print error message, continue validation as if nothing
	 * happened.
	 */
	INAC_IGNORE,
	/**
	 * Print error message in warning log level, continue validation as if
	 * nothing happened.
	 */
	INAC_WARN,
	/**
	 * Print error message in error log level, fail validation of the
	 * offending object (and all of its children).
	 */
	INAC_ERROR,
};

int incidence_init(void); /* incidence_destroy() is not needed. */
int incidence_update(json_t *);

void incidence_print(void);
enum incidence_action incidence_get_action(enum incidence_id);

#endif /* SRC_INCIDENCE_INCIDENCE_H_ */
