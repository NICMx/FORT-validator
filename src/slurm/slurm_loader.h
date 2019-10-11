#ifndef SRC_SLURM_SLURM_LOADER_H_
#define SRC_SLURM_SLURM_LOADER_H_

#include "rtr/db/db_table.h"
#include "slurm/db_slurm.h"

/*
 * Load the SLURM file/dir and try to apply it on @db_table, point to the SLURM
 * applied at @db_slurm.
 *
 * Return error only when there's a major issue on the process (no memory,
 * SLURM loaded but something happened applying it).
 *
 * Return 0 when there's no problem applying the SLURM:
 * - There's no SLURM configured
 * - The SLURM was successfully applied
 * - The @last_slurm was applied due to a syntax problem with a newer SLURM
 * - SLURM configured but couldn't be read (file doesn't exists, no permission)
 */
int slurm_apply(struct db_table **, struct db_slurm **);

#endif /* SRC_SLURM_SLURM_LOADER_H_ */
