#include "rtr/db/vrps.h"

#include <errno.h>
#include <time.h>

#include "config.h"
#include "log.h"
#include "object/tal.h"
#include "output_printer.h"
#include "rtr/db/db_table.h"
#include "slurm/slurm_loader.h"

int
handle_roa_v4(uint32_t as, struct ipv4_prefix const *prefix,
    uint8_t max_length, void *arg)
{
	return rtrhandler_handle_roa_v4(arg, as, prefix, max_length);
}

int
handle_roa_v6(uint32_t as, struct ipv6_prefix const * prefix,
    uint8_t max_length, void *arg)
{
	return rtrhandler_handle_roa_v6(arg, as, prefix, max_length);
}

int
handle_router_key(unsigned char const *ski, struct asn_range const *asns,
    unsigned char const *spk, void *arg)
{
	uint64_t asn;
	int error;

	/*
	 * TODO (warning) Umm... this is begging for a limit.
	 * If the issuer gets it wrong, we can iterate up to 2^32 times.
	 * The RFCs don't seem to care about this.
	 */
	for (asn = asns->min; asn <= asns->max; asn++) {
		error = rtrhandler_handle_router_key(arg, ski, asn, spk);
		if (error)
			return error;
	}

	return 0;
}

int
handle_aspa(struct aspa *aspa, void *arg)
{
	return rtrhandler_handle_aspa(arg, aspa);
}

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

	pr_op_info("Validation finished:");
	pr_op_info("- Valid ROAs: %u", db_table_roa_count(db));
	pr_op_info("- Valid Router Keys: %u", db_table_router_key_count(db));
	pr_op_info("- Valid ASPAs: %u", db_table_aspa_count(db));
	if (config_get_mode() == SERVER)
		pr_op_info("- Serial: %u", db_table_serial(db));
	if (start != ((time_t) -1) && finish != ((time_t) -1))
		pr_op_info("- Real execution time: %.0lfs", difftime(finish, start));

	if (rtr) {
		rtr->session = db_table_session(db);
		rtr->serial = db_table_serial(db);
	}

	db_table_destroy(db);
	return db ? 0 : EINVAL;
}
