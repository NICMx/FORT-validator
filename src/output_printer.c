#include "output_printer.h"

#include <arpa/inet.h>
#include <sys/types.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include <sys/socket.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include "config.h"
#include "file.h"
#include "log.h"
#include "rtr/db/vrp.h"

char addr_buf[INET6_ADDRSTRLEN];

static char const *
strv4addr(struct in_addr const *addr)
{
	return inet_ntop(AF_INET, addr, addr_buf, INET6_ADDRSTRLEN);
}

static char const *
strv6addr(struct in6_addr const *addr)
{
	return inet_ntop(AF_INET6, addr, addr_buf, INET6_ADDRSTRLEN);
}

static int
load_output_file(char const *output, FILE **result, bool *fopen)
{
	FILE *tmp;
	struct stat stat;
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

	error = file_write(output, &tmp, &stat);
	if (error) {
		*result = NULL;
		return error;
	}

	*fopen = true;
	*result = tmp;
	return 0;
}

static int
print_roa(struct vrp const *vrp, void *arg)
{
	FILE *out = arg;

	switch(vrp->addr_fam) {
	case AF_INET:
		fprintf(out, "AS%u,%s/%u,%u\n", vrp->asn,
		    strv4addr(&vrp->prefix.v4), vrp->prefix_length,
		    vrp->max_prefix_length);
		break;
	case AF_INET6:
		fprintf(out, "AS%u,%s/%u,%u\n", vrp->asn,
		    strv6addr(&vrp->prefix.v6), vrp->prefix_length,
		    vrp->max_prefix_length);
		break;
	default:
		pr_crit("Unknown family type");
	}

	return 0;
}

static int
print_to_hex(unsigned char *data, size_t len, char **out)
{
	char *tmp;
	char *init;
	int i;

	tmp = malloc(len * 3 + 1);
	if (tmp == NULL)
		return pr_enomem();

	init = tmp;
	for (i = 0; i < len * 3; i+=3) {
		*tmp = ':';
		tmp++;
		tmp += sprintf(tmp, "%02X", data[i/3]);
	}
	*tmp = '\0';

	*out = init;
	return 0;
}

/*
 * FIXME Improve this calls, maybe base64 encode and print?
 */
static int
print_router_key(struct router_key const *key, void *arg)
{
	FILE *out = arg;
	char *buf1;
	char *buf2;
	int error;

	error = print_to_hex(sk_info_get_ski(key->sk), RK_SKI_LEN, &buf1);
	if (error)
		return error;
	error = print_to_hex(sk_info_get_spk(key->sk),
	    sk_info_get_spk_len(key->sk), &buf2);
	if (error)
		return error;
	fprintf(out, "AS%u,%s,%s\n", key->as, buf1, buf2);
	free(buf1);
	free(buf2);

	return 0;
}

static int
open_file(char const *loc, FILE **out, bool *fopen)
{
	int error;

	error = load_output_file(loc, out, fopen);
	if (error)
		return pr_err("Error getting file '%s'", loc);

	/* No output configured */
	if (*out == NULL)
		return -ENOENT;

	return 0;
}

static void
print_roas(struct db_table *db)
{
	FILE *out;
	bool fopen;
	int error;

	out = NULL;
	error = open_file(config_get_output_roa(), &out, &fopen);
	if (error)
		return;

	fprintf(out, "ASN,Prefix,Max prefix length\n");
	error = db_table_foreach_roa(db, print_roa, out);
	if (fopen)
		file_close(out);
	if (error)
		pr_err("Error printing ROAs");
}

static void
print_router_keys(struct db_table *db)
{
	FILE *out;
	bool fopen;
	int error;

	out = NULL;
	error = open_file(config_get_output_bgpsec(), &out, &fopen);
	if (error)
		return;

	fprintf(out, "ASN,SKI,SPK\n");
	error = db_table_foreach_router_key(db, print_router_key, out);
	if (fopen)
		file_close(out);
	if (error)
		pr_err("Error printing Router Keys");
}

void
output_print_data(struct db_table *db)
{
	print_roas(db);
	print_router_keys(db);
}
