#include "content_info.h"
#include "signed_data.h"

const char *FILE_NAME = "/home/ydahhrk/rpki-cache/repository/"
		"ca.rg.net/rpki/RGnet/IZt-j9P0XqJjzM2Xi4RZKS60gOc.roa";

int
main(void)
{
	struct ContentInfo *cinfo;
	struct SignedData *sdata;
	int error;

	error = content_info_load(FILE_NAME, &cinfo);
	if (error)
		return error;

	error = signed_data_decode(&cinfo->content, &sdata);
	if (error) {
		content_info_free(cinfo);
		return error;
	}

//	asn_fprint(stdout, &asn_DEF_ContentInfo, cinfo);
//	printf("---------------------------------------------\n");
//	asn_fprint(stdout, &asn_DEF_SignedData, sdata);

	signed_data_free(sdata);
	content_info_free(cinfo);
	return 0;
}
