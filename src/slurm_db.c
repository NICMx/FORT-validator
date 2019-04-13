#include "slurm_db.h"

#include <stdbool.h>
#include "array_list.h"

ARRAY_LIST(al_filter_prefix, struct slurm_prefix)
ARRAY_LIST(al_assertion_prefix, struct slurm_prefix)
ARRAY_LIST(al_filter_bgpsec, struct slurm_bgpsec)
ARRAY_LIST(al_assertion_bgpsec, struct slurm_bgpsec)

struct arraylist_db {
	struct al_filter_prefix filter_pfx_al;
	struct al_assertion_prefix assertion_pfx_al;
	struct al_filter_bgpsec filter_bgps_al;
	struct al_assertion_bgpsec assertion_bgps_al;
} array_lists_db;

int
slurm_db_init(void)
{
	al_filter_prefix_init(&array_lists_db.filter_pfx_al);
	al_assertion_prefix_init(&array_lists_db.assertion_pfx_al);
	al_filter_bgpsec_init(&array_lists_db.filter_bgps_al);
	al_assertion_bgpsec_init(&array_lists_db.assertion_bgps_al);

	return 0;
}

int
slurm_db_add_prefix_filter(struct slurm_prefix *prefix)
{
	/* TODO check for exact duplicates and overwritten rules */
	return al_filter_prefix_add(&array_lists_db.filter_pfx_al, prefix);
}

int
slurm_db_add_prefix_assertion(struct slurm_prefix *prefix)
{
	/* TODO check for exact duplicates and overwritten rules */
	return al_assertion_prefix_add(&array_lists_db.assertion_pfx_al,
	    prefix);
}

int
slurm_db_add_bgpsec_filter(struct slurm_bgpsec *bgpsec)
{
	/* TODO check for exact duplicates and overwritten rules */
	return al_filter_bgpsec_add(&array_lists_db.filter_bgps_al, bgpsec);
}

int
slurm_db_add_bgpsec_assertion(struct slurm_bgpsec *bgpsec)
{
	/* TODO check for exact duplicates and overwritten rules */
	return al_assertion_bgpsec_add(&array_lists_db.assertion_bgps_al,
	    bgpsec);
}

static void
clean_slurm_prefix(struct slurm_prefix *prefix)
{
	if ((prefix->data_flag & SLURM_COM_FLAG_COMMENT) > 0)
		free((void *)prefix->comment);
}

static void
clean_slurm_bgpsec(struct slurm_bgpsec *bgpsec)
{
	if ((bgpsec->data_flag & SLURM_BGPS_FLAG_SKI) > 0)
		free(bgpsec->ski);
	if ((bgpsec->data_flag & SLURM_BGPS_FLAG_ROUTER_KEY) > 0)
		free(bgpsec->router_public_key);
	if ((bgpsec->data_flag & SLURM_COM_FLAG_COMMENT) > 0)
		free((void *)bgpsec->comment);
}

void
slurm_db_cleanup(void)
{
	/* TODO TEST DEBUG */
	struct slurm_prefix *p;
	struct slurm_bgpsec *b;
	ARRAYLIST_FOREACH(&array_lists_db.filter_pfx_al, p) {
		warnx("SLURM Prefix Filter:");
		if ((p->data_flag & SLURM_COM_FLAG_ASN) > 0)
			warnx("-->ASN: %u", p->asn);
		if ((p->data_flag & SLURM_COM_FLAG_COMMENT) > 0)
			warnx("-->Comment: %s", p->comment);
		if ((p->data_flag & SLURM_PFX_FLAG_PREFIX) > 0) {
			warnx("-->Addr fam: %u", p->addr_fam);
			warnx("-->Prefix len: %u", p->prefix_length);
		}
	}

	ARRAYLIST_FOREACH(&array_lists_db.filter_bgps_al, b) {
		warnx("SLURM BGPsec Filter:");
		if ((b->data_flag & SLURM_COM_FLAG_ASN) > 0)
			warnx("-->ASN: %u", b->asn);
		if ((b->data_flag & SLURM_COM_FLAG_COMMENT) > 0)
			warnx("-->Comment: %s", b->comment);
		if ((b->data_flag & SLURM_BGPS_FLAG_SKI) > 0) {
			warnx("-->SKI:");
			int i = 0;
			for (; i < b->ski_len; i++)
				warnx("---->[%d] = %02X", i, b->ski[i]);
		}
		if ((b->data_flag & SLURM_BGPS_FLAG_ROUTER_KEY) > 0) {
			warnx("-->SPKI:");
			int i = 0;
			for (; i < b->router_public_key_len; i++)
				warnx("---->[%d] = %02X", i,
				    b->router_public_key[i]);
		}
	}

	ARRAYLIST_FOREACH(&array_lists_db.assertion_pfx_al, p) {
		warnx("SLURM Prefix Assertion:");
		if ((p->data_flag & SLURM_COM_FLAG_ASN) > 0)
			warnx("-->ASN: %u", p->asn);
		if ((p->data_flag & SLURM_COM_FLAG_COMMENT) > 0)
			warnx("-->Comment: %s", p->comment);
		if ((p->data_flag & SLURM_PFX_FLAG_PREFIX) > 0) {
			warnx("-->Addr fam: %u", p->addr_fam);
			warnx("-->Prefix len: %u", p->prefix_length);
		}
	}

	ARRAYLIST_FOREACH(&array_lists_db.assertion_bgps_al, b) {
		warnx("SLURM BGPsec Assertion:");
		if ((b->data_flag & SLURM_COM_FLAG_ASN) > 0)
			warnx("-->ASN: %u", b->asn);
		if ((b->data_flag & SLURM_COM_FLAG_COMMENT) > 0)
			warnx("-->Comment: %s", b->comment);
		if ((b->data_flag & SLURM_BGPS_FLAG_SKI) > 0) {
			warnx("-->SKI:");
			int i = 0;
			for (; i < b->ski_len; i++)
				warnx("---->[%d] = %02X", i, b->ski[i]);
		}
		if ((b->data_flag & SLURM_BGPS_FLAG_ROUTER_KEY) > 0) {
			warnx("-->SPKI:");
			int i = 0;
			for (; i < b->router_public_key_len; i++)
				warnx("---->[%d] = %02X", i,
				    b->router_public_key[i]);
		}
	}
	warnx("**Deleting SLURM DB now**");

	al_filter_prefix_cleanup(&array_lists_db.filter_pfx_al,
	    clean_slurm_prefix);
	al_filter_bgpsec_cleanup(&array_lists_db.filter_bgps_al,
	    clean_slurm_bgpsec);
	al_assertion_prefix_cleanup(&array_lists_db.assertion_pfx_al,
	    clean_slurm_prefix);
	al_assertion_bgpsec_cleanup(&array_lists_db.assertion_bgps_al,
	    clean_slurm_bgpsec);
}
