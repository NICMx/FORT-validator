#ifndef SRC_SLURM_SLURM_DB_H_
#define SRC_SLURM_SLURM_DB_H_

#include <stdbool.h>
#include "slurm/slurm_parser.h"

typedef int (*assertion_pfx_foreach_cb)(struct slurm_prefix *, void *);

void slurm_db_init(void);

int slurm_db_add_prefix_filter(struct slurm_prefix *, int);
int slurm_db_add_prefix_assertion(struct slurm_prefix *, int);
int slurm_db_add_bgpsec_filter(struct slurm_bgpsec *, int);
int slurm_db_add_bgpsec_assertion(struct slurm_bgpsec *, int);

bool slurm_db_vrp_is_filtered(struct vrp const *vrp);
int slurm_db_foreach_assertion_prefix(assertion_pfx_foreach_cb, void *);

void slurm_db_cleanup(void);

#endif /* SRC_SLURM_SLURM_DB_H_ */
