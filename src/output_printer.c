#include "output_printer.h"

#include "config.h"
#include "crypto/base64.h"
#include "file.h"
#include "log.h"

typedef struct json_out {
	FILE *file;
	bool first;
} JSON_OUT;

static FILE *
load_output_file(char const *filename)
{
	FILE *out;

	if (filename == NULL)
		return NULL;

	if (strcmp(filename, "-") == 0)
		return stdout;

	return (file_write(filename, "w", &out) == 0) ? out : NULL;
}

static int
print_roa_csv(struct vrp const *vrp, void *arg)
{
	char addr_buf[INET6_ADDRSTRLEN];

	if (vrp->addr_fam != AF_INET && vrp->addr_fam != AF_INET6)
		pr_crit("Unknown family type");

	fprintf(arg, "AS%u,%s/%u,%u\n", vrp->asn,
	    inet_ntop(vrp->addr_fam, &vrp->prefix, addr_buf, INET6_ADDRSTRLEN),
	    vrp->prefix_length, vrp->max_prefix_length);

	return 0;
}

static int
print_roa_json(struct vrp const *vrp, void *arg)
{
	JSON_OUT *json_out = arg;
	FILE *out;
	char addr_buf[INET6_ADDRSTRLEN];

	out = json_out->file;
	if (!json_out->first)
		fprintf(out, ",");

	if (vrp->addr_fam != AF_INET && vrp->addr_fam != AF_INET6)
		pr_crit("Unknown family type");

	fprintf(out,
	    "\n  { \"asn\": \"AS%u\", \"prefix\": \"%s/%u\", \"maxLength\": %u }",
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
	char *buf1, *buf2;

	if (!base64url_encode(key->ski, RK_SKI_LEN, &buf1)) {
		op_crypto_err("Cannot encode SKI.");
		return 0; /* Skip it, I guess */
	}

	if (!base64url_encode(key->spk, RK_SPKI_LEN, &buf2)) {
		op_crypto_err("Cannot encode SPK.");
		free(buf1);
		return 0; /* Skip it, I guess */
	}

	fprintf(arg, "AS%u,%s,%s\n", key->as, buf1, buf2);

	free(buf2);
	free(buf1);
	return 0;
}

/* Print as base64url strings without trailing pad */
static int
print_router_key_json(struct router_key const *key, void *arg)
{
	JSON_OUT *json_out = arg;
	FILE *out;
	char *buf1, *buf2;

	if (!base64url_encode(key->ski, RK_SKI_LEN, &buf1)) {
		op_crypto_err("Cannot encode SKI.");
		return 0; /* Skip it, I guess */
	}

	if (!base64url_encode(key->spk, RK_SPKI_LEN, &buf2)) {
		op_crypto_err("Cannot encode SPK.");
		free(buf1);
		return 0; /* Skip it, I guess */
	}

	out = json_out->file;
	if (!json_out->first)
		fprintf(out, ",");

	fprintf(out,
	    "\n  { \"asn\": \"AS%u\", \"ski\": \"%s\", \"spki\": \"%s\" }",
	    key->as,
	    buf1,
	    buf2);

	free(buf2);
	free(buf1);
	json_out->first = false;
	return 0;
}

static void
print_roas(struct db_table const *db)
{
	FILE *out;
	JSON_OUT json_out;
	int error;

	out = load_output_file(config_get_output_roa());
	if (out == NULL)
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

	if (error)
		pr_op_err("Error printing ROAs: %s", strerror(error));
	if (out != stdout)
		file_close(out);
}

static void
print_router_keys(struct db_table const *db)
{
	FILE *out;
	JSON_OUT json_out;
	int error;

	out = load_output_file(config_get_output_bgpsec());
	if (out == NULL)
		return;

	if (config_get_output_format() == OFM_CSV) {
		fprintf(out, "ASN,Subject Key Identifier,Subject Public Key Info\n");
		error = db_table_foreach_router_key(db, print_router_key_csv, out);

	} else {
		json_out.file = out;
		json_out.first = true;

		fprintf(out, "{ \"router-keys\" : [");
		error = db_table_foreach_router_key(db, print_router_key_json, &json_out);
		fprintf(out, "\n]}\n");
	}

	if (error)
		pr_op_err("Error printing Router Keys: %s", strerror(error));
	if (out != stdout)
		file_close(out);
}

void
output_print_data(struct db_table const *db)
{
	print_roas(db);
	print_router_keys(db);
}
