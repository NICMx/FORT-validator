#ifndef SRC_SLURM_DB_H_
#define SRC_SLURM_DB_H_

#include "slurm_parser.h"

struct slurm_prefix_list {
	struct slurm_prefix *list;
	unsigned int len;
};

struct slurm_bgpsec_list {
	struct slurm_bgpsec *list;
	unsigned int len;
};

struct slurm_db {
	struct slurm_prefix_list prefix_filters;
	struct slurm_bgpsec_list bgpsec_filters;
	struct slurm_prefix_list prefix_assertions;
	struct slurm_bgpsec_list bgpsec_assertions;
};

int slurm_db_init(void);

int slurm_db_add_prefix_filter(struct slurm_prefix *);
int slurm_db_add_prefix_assertion(struct slurm_prefix *);
int slurm_db_add_bgpsec_filter(struct slurm_bgpsec *);
int slurm_db_add_bgpsec_assertion(struct slurm_bgpsec *);

void slurm_db_cleanup(void);

#endif /* SRC_SLURM_DB_H_ */
