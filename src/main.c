#include <errno.h>

#include "common.h"
#include "asn1/content_info.h"
#include "asn1/manifest.h"
#include "asn1/roa.h"
#include "asn1/signed_data.h"

int
try_roa(char *file_name)
{
	struct ContentInfo *cinfo;
	struct SignedData *sdata;
	struct RouteOriginAttestation *roa;
	int error;

	error = content_info_load(file_name, &cinfo);
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

int
try_manifest(char *file_name)
{
	struct ContentInfo *cinfo;
	struct SignedData *sdata;
	struct Manifest *manifest;
	int error;

	error = content_info_load(file_name, &cinfo);
	if (error)
		return error;

	error = signed_data_decode(&cinfo->content, &sdata);
	if (error) {
		content_info_free(cinfo);
		return error;
	}

	error = manifest_decode(sdata, &manifest);
	if (error) {
		signed_data_free(sdata);
		content_info_free(cinfo);
		return error;
	}

	asn_fprint(stdout, &asn_DEF_Manifest, manifest);

	manifest_free(manifest);
	signed_data_free(sdata);
	content_info_free(cinfo);
	return 0;
}

int
main(int argc, char **argv)
{
	int error;

	if (argc < 3) {
		pr_debug0("argc < 3");
		return -EINVAL;
	}

//	error = try_roa(argv[1]);
//	if (error)
//		return error;

	error = try_manifest(argv[2]);
	if (error)
		return error;

	return 0;
}
