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
load_output_file(FILE **result, bool *fopen)
{
	FILE *tmp;
	struct stat stat;
	char const *output = config_get_output_roa();
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
	if (error)
		return error;

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

void
output_print_roas(struct roa_table *roas)
{
	FILE *out;
	bool fopen;
	int error;

	error = load_output_file(&out, &fopen);
	if (error) {
		pr_err("Error getting file '%s'", config_get_output_roa());
		return;
	}

	/* No output configured */
	if (out == NULL)
		return;

	fprintf(out, "ASN,Prefix,Max prefix length\n");
	error = roa_table_foreach_roa(roas, print_roa, out);
	if (fopen)
		file_close(out);
	if (error) {
		pr_err("Error printing ROAs");
		return;
	}
}
