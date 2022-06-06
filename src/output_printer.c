#include "output_printer.h"

#include <arpa/inet.h>
#include "common.h"
#include "config.h"
#include "file.h"
#include "log.h"
#include "crypto/base64.h"
#include "types/vrp.h"

static char addr_buf[INET6_ADDRSTRLEN];

typedef struct json_out {
	FILE *file;
	bool first;
} JSON_OUT;

static int
load_output_file(char const *output, FILE **result, bool *fopen)
{
	FILE *tmp;
	int error;

	if (output == NULL) {
		*result = NULL;
		return 0;
	}

	*fopen = false;
	if (strcmp(output, "-") == 0) {
		*result = stdout;
		return 0;
	}

	error = file_write(output, &tmp);
	if (error) {
		*result = NULL;
		return error;
	}

	*fopen = true;
	*result = tmp;
	return 0;
}

static int
print_roa_csv(struct vrp const *vrp, void *arg)
{
	FILE *out = arg;

	if (vrp->addr_fam != AF_INET && vrp->addr_fam != AF_INET6)
		pr_crit("Unknown family type");

	fprintf(out, "AS%u,%s/%u,%u\n", vrp->asn,
	    inet_ntop(vrp->addr_fam, &vrp->prefix, addr_buf, INET6_ADDRSTRLEN),
	    vrp->prefix_length, vrp->max_prefix_length);

	return 0;
}

static int
print_roa_json(struct vrp const *vrp, void *arg)
{
	JSON_OUT *json_out = arg;
	FILE *out;

	out = json_out->file;
	if (!json_out->first)
		fprintf(out, ",");

	if (vrp->addr_fam != AF_INET && vrp->addr_fam != AF_INET6)
		pr_crit("Unknown family type");

	fprintf(out,
	    "\n  { \"asn\" : \"AS%u\", \"prefix\" : \"%s/%u\", \"maxLength\" : %u }",
	    vrp->asn,
	    inet_ntop(vrp->addr_fam, &vrp->prefix, addr_buf, INET6_ADDRSTRLEN),
	    vrp->prefix_length,
	    vrp->max_prefix_length);

	json_out->first = false;
	return 0;
}

/* Print as base64url strings without trailing pad */
static int
print_router_key_csv(struct router_key const *key, void *arg)
{
	FILE *out = arg;
	char *buf1, *buf2;
	int error;

	error = base64url_encode(key->ski, RK_SKI_LEN, &buf1);
	if (error)
		return error;

	error = base64url_encode(key->spk, RK_SPKI_LEN, &buf2);
	if (error)
		goto free1;

	fprintf(out, "AS%u,%s,%s\n", key->as, buf1, buf2);

	free(buf2);
free1:
	free(buf1);
	return error;
}

/* Print as base64url strings without trailing pad */
static int
print_router_key_json(struct router_key const *key, void *arg)
{
	JSON_OUT *json_out = arg;
	FILE *out;
	char *buf1, *buf2;
	int error;

	error = base64url_encode(key->ski, RK_SKI_LEN, &buf1);
	if (error)
		return error;

	error = base64url_encode(key->spk, RK_SPKI_LEN, &buf2);
	if (error)
		goto free1;

	out = json_out->file;
	if (!json_out->first)
		fprintf(out, ",");

	fprintf(out,
	    "\n  { \"asn\" : \"AS%u\", \"ski\" : \"%s\", \"spki\" : \"%s\" }",
	    key->as,
	    buf1,
	    buf2);

	free(buf2);
free1:
	free(buf1);
	json_out->first = false;
	return error;
}

static int
open_file(char const *loc, FILE **out, bool *fopen)
{
	int error;

	error = load_output_file(loc, out, fopen);
	if (error)
		return pr_op_err("Error getting file '%s'", loc);

	/* No output configured */
	if (*out == NULL)
		return -ENOENT;

	return 0;
}

static void
print_roas(struct db_table const *db)
{
	FILE *out;
	JSON_OUT json_out;
	bool fopen;
	int error;

	out = NULL;
	error = open_file(config_get_output_roa(), &out, &fopen);
	if (error)
		return;

	if (config_get_output_format() == OFM_CSV) {
		fprintf(out, "ASN,Prefix,Max prefix length\n");
		error = db_table_foreach_roa(db, print_roa_csv, out);
	} else {
		json_out.file = out;
		json_out.first = true;

		fprintf(out, "{ \"roas\" : [");
		error = db_table_foreach_roa(db, print_roa_json, &json_out);
		fprintf(out, "\n]}\n");
	}

	if (fopen)
		file_close(out);
	if (error)
		pr_op_err("Error printing ROAs");
}

static void
print_router_keys(struct db_table const *db)
{
	FILE *out;
	JSON_OUT json_out;
	bool fopen;
	int error;

	out = NULL;
	error = open_file(config_get_output_bgpsec(), &out, &fopen);
	if (error)
		return;

	if (config_get_output_format() == OFM_CSV) {
		fprintf(out,
		    "ASN,Subject Key Identifier,Subject Public Key Info\n");
		error = db_table_foreach_router_key(db, print_router_key_csv,
		    out);
	} else {
		json_out.file = out;
		json_out.first = true;

		fprintf(out, "{ \"router-keys\" : [");
		error = db_table_foreach_router_key(db, print_router_key_json,
		    &json_out);
		fprintf(out, "\n]}\n");
	}

	if (fopen)
		file_close(out);
	if (error)
		pr_op_err("Error printing Router Keys");
}

void
output_print_data(struct db_table const *db)
{
	print_roas(db);
	print_router_keys(db);
}
