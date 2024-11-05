#include "validation_handler.h"

#include "rtr/db/db_table.h"

static struct db_table *table;

void
vhandle_init(void)
{
	table = db_table_create();
}

struct db_table *
vhandle_claim(void)
{
	struct db_table *result = table;
	table = NULL;
	return result;
}

int
vhandle_roa_v4(uint32_t as, struct ipv4_prefix const *pfx, uint8_t maxlen)
{
	return rtrhandler_handle_roa_v4(table, as, pfx, maxlen);
}

int
vhandle_roa_v6(uint32_t as, struct ipv6_prefix const *pfx, uint8_t maxlen)
{
	return rtrhandler_handle_roa_v6(table, as, pfx, maxlen);
}

int
vhandle_router_key(unsigned char const *ski, struct asn_range const *asns,
    unsigned char const *spk)
{
	uint64_t asn;
	int error;

	/*
	 * TODO (warning) Umm... this is begging for a limit.
	 * If the issuer gets it wrong, we can iterate up to 2^32 times.
	 * The RFCs don't seem to care about this.
	 */
	for (asn = asns->min; asn <= asns->max; asn++) {
		error = rtrhandler_handle_router_key(table, ski, asn, spk);
		if (error)
			return error;
	}

	return 0;
}
