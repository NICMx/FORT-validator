#include "object/roa.h"

#include <errno.h>
#include <arpa/inet.h>
#include <libcmscodec/RouteOriginAttestation.h>

#include "common.h"
#include "log.h"
#include "asn1/oid.h"
#include "object/signed_object.h"

bool is_roa(char const *file_name)
{
	return file_has_extension(file_name, "roa");
}

static int
validate_roa(struct validation *state, struct RouteOriginAttestation *roa)
{
	/* rfc6482#section-3.1 */
	if (roa->version != 0) {
		pr_err(state, "ROA's version (%ld) is nonzero.", roa->version);
		return -EINVAL;
	}

	/* rfc6482#section-3.2 */
	if (roa->ipAddrBlocks.list.array == NULL)
		return -EINVAL;

	return 0;
}

static int
print_addr(struct validation *state, long asn, uint8_t family,
    struct ROAIPAddress *roa_addr)
{
	union {
		struct in6_addr ip6;
		struct in_addr ip4;
	} addr;
	union {
		char ip6[INET6_ADDRSTRLEN];
		char ip4[INET_ADDRSTRLEN];
	} str;
	int prefix_len;
	const char *str2;

	switch (family) {
	case 1:
		family = AF_INET;
		break;
	case 2:
		family = AF_INET6;
		break;
	default:
		pr_err(state, "Unknown family value: %u", family);
		return -EINVAL;
	}

	/*
	 * TODO maybe validate roa_addr->address.size > 0,
	 * roa_addr->address.size <= actual address max size,
	 * roa_addr->address.bits_unused < 8,
	 * and roa_addr->address.buf lacks nonzero unused bits.
	 * Also test 0/0.
	 */

	memset(&addr, 0, sizeof(addr));
	memcpy(&addr, roa_addr->address.buf, roa_addr->address.size);
	str2 = inet_ntop(family, &addr, str.ip6, sizeof(str));
	if (str2 == NULL)
		return pr_errno(state, errno, "Cannot parse IP address");

	prefix_len = 8 * roa_addr->address.size - roa_addr->address.bits_unused;

	printf("%ld,%s/%d,", asn, str2, prefix_len);

	if (roa_addr->maxLength != NULL)
		printf("%ld", *roa_addr->maxLength);
	else
		printf("%d", prefix_len);

	printf("\n");
	return 0;
}

static int
__handle_roa(struct validation *state, struct RouteOriginAttestation *roa)
{
	struct ROAIPAddressFamily *block;
	int b;
	int a;
	int error;

	for (b = 0; b < roa->ipAddrBlocks.list.count; b++) {
		block = roa->ipAddrBlocks.list.array[0];
		if (block == NULL)
			return -EINVAL;

		if (block->addressFamily.size != 2)
			return -EINVAL;
		if (block->addressFamily.buf[0] != 0)
			return -EINVAL;
		if (block->addressFamily.buf[1] != 1
		    && block->addressFamily.buf[1] != 2)
			return -EINVAL;

		if (block->addresses.list.array == NULL)
			return -EINVAL;
		for (a = 0; a < block->addresses.list.count; a++) {
			error = print_addr(state, roa->asID,
			    block->addressFamily.buf[1],
			    block->addresses.list.array[a]);
			if (error)
				return error;
		}
	}

	return 0;
}

int handle_roa(struct validation *state, char const *file)
{
	static OID oid = OID_ROA;
	struct oid_arcs arcs = OID2ARCS(oid);
	struct RouteOriginAttestation *roa;
	int error;

	error = signed_object_decode(state, file,
	    &asn_DEF_RouteOriginAttestation, &arcs, (void **) &roa);
	if (error)
		return error;

	error = validate_roa(state, roa);
	if (!error)
		error = __handle_roa(state, roa);

	ASN_STRUCT_FREE(asn_DEF_RouteOriginAttestation, roa);
	return error;
}
