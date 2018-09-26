#include <errno.h>

#include "common.h"
#include "asn1/content_info.h"
#include "asn1/roa.h"
#include "asn1/signed_data.h"

int
main(int argc, char **argv)
{
	struct ContentInfo *cinfo;
	struct SignedData *sdata;
	struct RouteOriginAttestation *roa;
	int error;

	if (argc < 2) {
		pr_debug0("argc < 2");
		return -EINVAL;
	}

	error = content_info_load(argv[1], &cinfo);
	if (error)
		return error;

	error = signed_data_decode(&cinfo->content, &sdata);
	if (error) {
		content_info_free(cinfo);
		return error;
	}

	error = roa_decode(sdata, &roa);
	if (error) {
		signed_data_free(sdata);
		content_info_free(cinfo);
		return error;
	}

	asn_fprint(stdout, &asn_DEF_RouteOriginAttestation, roa);

	roa_free(roa);
	signed_data_free(sdata);
	content_info_free(cinfo);
	return 0;
}
