#ifndef SRC_SLURM_SLURM_PARSER_H_
#define SRC_SLURM_SLURM_PARSER_H_

#include "rtr/db/db_table.h"
#include "slurm/db_slurm.h"

struct slurm_parser_params {
	struct db_table *db_table;
	struct db_slurm *db_slurm;
	unsigned int 	cur_ctx; /* Context (file number) */
};

int slurm_parse(char const *, void *);


#endif /* SRC_SLURM_SLURM_PARSER_H_ */
