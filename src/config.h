#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdbool.h>

struct rpki_config {
	/* tal file path*/
	char *tal;
	/* Local repository path */
	char *local_repository;
	/* Disable rsync downloads */
	bool disable_rsync;
	/* Shuffle uris in tal */
	bool shuffle_uris;
	/*
	 * rfc6487#section-7.2, last paragraph.
	 * Prevents arbitrarily long paths and loops.
	 */
	unsigned int maximum_certificate_depth;
};

void config_set(struct rpki_config *);

char const *config_get_tal(void);
char const *config_get_local_repository(void);
bool config_get_disable_rsync(void);
bool config_get_shuffle_uris(void);
unsigned int config_get_max_cert_depth(void);

#endif /* SRC_CONFIG_H_ */
