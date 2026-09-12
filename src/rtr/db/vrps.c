#include "rtr/db/vrps.h"

#include <errno.h>
#include <sys/stat.h>

#include "config.h"
#include "log.h"
#include "object/tal.h"
#include "output_printer.h"
#include "slurm/slurm_loader.h"

/*
 * High level validator function.
 *
 * - Downloads tree
 * - Validates tree
 * - Updates RTR state
 */
static struct db_table *
__vrps_update(void)
{
	struct db_table *db;

	db = perform_standalone_validation();
	if (!db)
		return NULL;

	if (slurm_apply(db) != 0)
		goto fail;

	db_table_sort(db);

	if (db_table_cache(db) != 0)
		goto fail;

	output_print_data(db);

	return db;

fail:	db_table_destroy(db);
	return NULL;
}

/*
 * Highest level validator function.
 *
 * - Downloads tree
 * - Validates tree
 * - Updates RTR state
 * - Logs status
 *
 * TODO (#50) remove this wrapper once Prometheus is implemented
 */
int
vrps_update(struct rtr_metadata *rtr)
{
	struct db_table *db;
	time_t start, finish;

	start = time(NULL);
	db = __vrps_update();
	finish = time(NULL);

	pr_inf("Validation finished:");
	pr_inf("- Valid ROAs: %u", db_table_roa_count(db));
	pr_inf("- Valid Router Keys: %u", db_table_router_key_count(db));
	pr_inf("- Valid ASPAs: %u", db_table_aspa_count(db));
	if (config_get_mode() == SERVER)
		pr_inf("- Serial: %u", db_table_serial(db));
	if (start != ((time_t) -1) && finish != ((time_t) -1))
		pr_inf("- Real execution time: %.0lfs", difftime(finish, start));

	if (rtr) {
		rtr->session = db_table_session(db);
		rtr->serial = db_table_serial(db);
	}

	db_table_destroy(db);
	return db ? 0 : EINVAL;
}
