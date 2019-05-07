#ifndef SRC_SLURM_SLURM_DB_H_
#define SRC_SLURM_SLURM_DB_H_

#include <stdbool.h>
#include "slurm/slurm_parser.h"

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

typedef int (*assertion_pfx_foreach_cb)(struct slurm_prefix *, void *);

void slurm_db_init(void);

int slurm_db_add_prefix_filter(struct slurm_prefix *);
int slurm_db_add_prefix_assertion(struct slurm_prefix *);
int slurm_db_add_bgpsec_filter(struct slurm_bgpsec *);
int slurm_db_add_bgpsec_assertion(struct slurm_bgpsec *);

bool slurm_db_vrp_is_filtered(struct vrp *vrp);
int slurm_db_foreach_assertion_prefix(assertion_pfx_foreach_cb, void *);

void slurm_db_cleanup(void);

#endif /* SRC_SLURM_SLURM_DB_H_ */
