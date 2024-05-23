/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn1/asn1c/xer_encoder.h"

#include "asn1/asn1c/asn_internal.h"

/*
 * The XER encoder of any type. May be invoked by the application.
 */
asn_enc_rval_t
xer_encode(const asn_TYPE_descriptor_t *td, const void *sptr,
           enum xer_encoder_flags_e xer_flags, asn_app_consume_bytes_f *cb,
           void *app_key) {
	asn_enc_rval_t er = { 0 };
	asn_enc_rval_t tmper;
	const char *mname;
	size_t mlen;
	int xcan = (xer_flags & XER_F_CANONICAL) ? 1 : 2;

	if(!td || !sptr) goto cb_failed;

	mname = td->xml_tag;
	mlen = strlen(mname);

	ASN__CALLBACK3("<", 1, mname, mlen, ">", 1);

	tmper = td->op->xer_encoder(td, sptr, 1, xer_flags, cb, app_key);
	if(tmper.encoded == -1) return tmper;
	er.encoded += tmper.encoded;

	ASN__CALLBACK3("</", 2, mname, mlen, ">\n", xcan);

	ASN__ENCODED_OK(er);
cb_failed:
	ASN__ENCODE_FAILED;
}

/*
 * This is a helper function for xer_fprint, which directs all incoming data
 * into the provided file descriptor.
 */
static int
xer__print2fp(const void *buffer, size_t size, void *app_key) {
	FILE *stream = (FILE *)app_key;

	if(fwrite(buffer, 1, size, stream) != size)
		return -1;

	return 0;
}

int
xer_fprint(FILE *stream, const asn_TYPE_descriptor_t *td, const void *sptr) {
    asn_enc_rval_t er;

	if(!stream) stream = stdout;
	if(!td || !sptr)
		return -1;

	er = xer_encode(td, sptr, XER_F_BASIC, xer__print2fp, stream);
	if(er.encoded == -1)
		return -1;

	return fflush(stream);
}
