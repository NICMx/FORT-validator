#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdbool.h>

struct rpki_config {
	/* tal file path*/
	char *tal;
	/* Local repository path */
	char *local_repository;
	/* Disable rsync downloads */
	bool enable_rsync;
	/* Shuffle uris in tal */
	bool shuffle_uris;
	/* Configuration file path */
	bool flag_config;
};

int set_config_from_file(char *, struct rpki_config *);

#endif /* SRC_CONFIG_H_ */
