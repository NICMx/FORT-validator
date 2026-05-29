#include "rtr/pdu_handler.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "alloc.h"
#include "log.h"
#include "data_structure/common.h"
#include "rtr/err_pdu.h"
#include "rtr/pdu_sender.h"

struct rtr_stream {
	int fd;
	uint8_t ver; /* RTR version */

	char const *type;
	size_t rawlen;
	int (*send)(struct rtr_stream *, unsigned char const *, int);
};

static uint32_t
read_u32(unsigned char const *raw)
{
	return (((unsigned int)(raw[0])) << 24)
	     | (((unsigned int)(raw[1])) << 16)
	     | (((unsigned int)(raw[2])) <<  8)
	     | (((unsigned int)(raw[3])) <<  0);
}

static int
send_vrp4(struct rtr_stream *rs, unsigned char const *raw, int flag)
{
	struct vrp vrp;

	vrp.addr_fam = AF_INET;
	vrp.asn = read_u32(raw);
	memcpy(&vrp.prefix.v4, raw + 4, 4);
	vrp.prefix_length = raw[8];
	vrp.max_prefix_length = raw[9];

	return send_prefix_pdu(rs->fd, rs->ver, &vrp, flag);
}

static int
send_vrp6(struct rtr_stream *rs, unsigned char const *raw, int flag)
{
	struct vrp vrp;

	vrp.addr_fam = AF_INET6;
	vrp.asn = read_u32(raw);
	memcpy(&vrp.prefix.v6, raw + 4, 16);
	vrp.prefix_length = raw[20];
	vrp.max_prefix_length = raw[21];

	return send_prefix_pdu(rs->fd, rs->ver, &vrp, flag);
}

static int
send_rk(struct rtr_stream *rs, unsigned char const *raw, int flag)
{
	struct router_key rk;

	rk.as = read_u32(raw);
	memcpy(rk.ski, raw + 4, RK_SKI_LEN);
	memcpy(rk.spk, raw + 4 + RK_SKI_LEN, RK_SPKI_LEN);

	return send_router_key_pdu(rs->fd, rs->ver, &rk, flag);
}

static int
parse_providers(unsigned char const *hdr, FILE *file,
    struct aspa_providers *providers)
{
	array_index i;
	unsigned char buf[4];
	int error;

	providers->count = read_u32(hdr + 4);
	providers->asids = pcalloc(sizeof(uint32_t), providers->count);

	for (i = 0; i < providers->count; i++) {
		if (fread(buf, 4, 1, file) == 1) {
			providers->asids[i] = read_u32(buf);
		} else if (feof(file)) {
			error = pr_op_err("File ended prematurely");
			goto end;
		} else if (ferror(file)) {
			error = errno;
			if (!error)
				error = EINVAL;
			pr_op_err("File read failure: %s", strerror(error));
			goto end;
		}
	}

	return 0;

end:	free(providers->asids);
	return error;
}

static int
send_aspa_announce(int fd, uint8_t ver, unsigned char const *hdr, FILE *file)
{
	struct aspa aspa = { 0 };
	int error;

	aspa.customer = read_u32(hdr);
	error = parse_providers(hdr, file, &aspa.providers);
	if (error)
		return error;

	error = send_aspa_announce_pdu(fd, ver, &aspa);

	free(aspa.providers.asids);
	return error;
}

/* Throw away the providers list */
static int
skip_providers(unsigned char const *hdr, FILE *file)
{
	unsigned char buf[256];
	unsigned int total; /* Total providers */
	unsigned int want; /* Providers we want to read */
	unsigned int red; /* Actual read providers */
	int error;

	for (total = read_u32(hdr + 4); total > 0; total -= red) {
		want = (total < 64) ? total : 64;
		red = fread(buf, 4, want, file);
		if (want != red) {
			if (feof(file))
				return pr_op_err("File ended prematurely");
			if (ferror(file)) {
				error = errno;
				if (!error)
					error = EINVAL;
				pr_op_err("File read failure: %s", strerror(error));
				return error;
			}
		}
	}

	return 0;
}

static int
send_aspa_withdraw(int fd, uint8_t ver, unsigned char const *hdr, FILE *file)
{
	int error;

	error = skip_providers(hdr, file);
	if (error)
		return error;

	return send_aspa_withdraw_pdu(fd, ver, read_u32(hdr));
}

static unsigned char const *
next_chunk(FILE *file, unsigned char *buf, size_t size, int *error)
{
	int n;

again:	n = fread(buf, size, 1, file);
	if (n < 1) {
		if (ferror(file)) {
			*error = errno;
			if (!*error)
				*error = EINVAL;
			pr_op_err("File read failure: %s", strerror(*error));
			return NULL;
		}
		if (feof(file))
			return NULL;
		goto again; /* Dead code, unless fread() is borked */
	}

	return buf;
}

static int
send_serial(struct rtr_stream *stream, serial_t serial)
{
	FILE *file = 0;
	unsigned char *buf;
	unsigned char const *chunk;
	int error;

	buf = pmalloc(stream->rawlen);

	error = rtr_open_file(serial, stream->type, "r", &file);
	if (error)
		goto end;

	do {
		chunk = next_chunk(file, buf, stream->rawlen, &error);
		if (!chunk || error)
			break;
		error = stream->send(stream, chunk, FLAG_ANNOUNCEMENT);
	} while (!error);

	fclose(file);
end:	free(buf);
	return error;
}

static int
send_aspas(int fd, uint8_t ver, serial_t serial)
{
	FILE *file = 0;
	unsigned char buf[8];
	unsigned char const *chunk;
	int error;

	error = rtr_open_file(serial, "aspa", "r", &file);
	if (error)
		return error;

	do {
		chunk = next_chunk(file, buf, 8, &error);
		if (!chunk || error)
			break;
		error = send_aspa_announce(fd, ver, chunk, file);
	} while (!error);

	fclose(file);
	return error;
}

static int
load_rtr_metadata(struct rtr_metadata *rtr, uint8_t version)
{
	struct rtr_index idx;
	int error;

	error = rtridx_load(&idx, false);
	if (error)
		return error;
	if (idx.serials == NULL) {
		error = ENOENT;
		goto end;
	}

	rtr->session = idx.session + version;
	rtr->serial = idx.serials->serial;

end:	rtridx_cleanup(&idx);
	return error;
}

int
handle_reset_query_pdu(struct rtr_request *request)
{
	struct rtr_metadata rtr;
	struct rtr_stream stream;
	int error;

	pr_op_debug("Reset Query. Request version: %u",
	    request->pdu.rtr_version);

	stream.fd = request->fd;
	stream.ver = request->pdu.rtr_version;

	error = load_rtr_metadata(&rtr, stream.ver);
	switch (error) {
	case 0:
		break;
	case ENOENT:
		return err_pdu_send_no_data_available(stream.fd, stream.ver);
	default:
		goto internal_error;
	}

	error = send_cache_response_pdu(stream.fd, stream.ver, rtr.session);
	if (error)
		return error;

	stream.type = "vrp4";
	stream.rawlen = 10;
	stream.send = send_vrp4;
	error = send_serial(&stream, rtr.serial);
	if (error)
		goto internal_error;

	stream.type = "vrp6";
	stream.rawlen = 22;
	stream.send = send_vrp6;
	error = send_serial(&stream, rtr.serial);
	if (error)
		goto internal_error;

	if (stream.ver >= RTR_V1) {
		stream.type = "rk";
		stream.rawlen = 4 + RK_SKI_LEN + RK_SPKI_LEN;
		stream.send = send_rk;
		error = send_serial(&stream, rtr.serial);
		if (error)
			goto internal_error;
	}

	if (stream.ver >= RTR_V2) {
		error = send_aspas(stream.fd, stream.ver, rtr.serial);
		if (error)
			goto internal_error;
	}

	return send_end_of_data_pdu(stream.fd, stream.ver, rtr.session, rtr.serial);

internal_error:
	return err_pdu_send_internal_error(stream.fd, stream.ver);
}

static int
send_delta(struct rtr_stream *rs, serial_t oserial, serial_t nserial)
{
	FILE *ofile = NULL;
	FILE *nfile = NULL;
	unsigned char *buf1;
	unsigned char *buf2;
	unsigned char const *ochunk;
	unsigned char const *nchunk;
	int cmp;
	int error;

	buf1 = pmalloc(rs->rawlen);
	buf2 = pmalloc(rs->rawlen);

	error = rtr_open_file(oserial, rs->type, "r", &ofile);
	if (error)
		goto end;
	error = rtr_open_file(nserial, rs->type, "r", &nfile);
	if (error)
		goto end;

	ochunk = next_chunk(ofile, buf1, rs->rawlen, &error);
	if (error)
		goto end;
	nchunk = next_chunk(nfile, buf2, rs->rawlen, &error);
	if (error)
		goto end;

	while (ochunk && nchunk) {
		cmp = memcmp(ochunk, nchunk, rs->rawlen);
		if (cmp < 0) {
			error = rs->send(rs, ochunk, FLAG_WITHDRAWAL);
			if (error)
				goto end;
			ochunk = next_chunk(ofile, buf1, rs->rawlen, &error);
			if (error)
				goto end;

		} else if (cmp > 0) {
			error = rs->send(rs, nchunk, FLAG_ANNOUNCEMENT);
			if (error)
				goto end;
			nchunk = next_chunk(nfile, buf2, rs->rawlen, &error);
			if (error)
				goto end;

		} else {
			ochunk = next_chunk(ofile, buf1, rs->rawlen, &error);
			if (error)
				goto end;
			nchunk = next_chunk(nfile, buf2, rs->rawlen, &error);
			if (error)
				goto end;
		}
	}

	while (ochunk) {
		error = rs->send(rs, ochunk, FLAG_WITHDRAWAL);
		if (error)
			goto end;
		ochunk = next_chunk(ofile, buf1, rs->rawlen, &error);
		if (error)
			goto end;
	}

	while (nchunk) {
		error = rs->send(rs, nchunk, FLAG_ANNOUNCEMENT);
		if (error)
			goto end;
		nchunk = next_chunk(nfile, buf2, rs->rawlen, &error);
		if (error)
			goto end;
	}

end:	if (nfile) fclose(nfile);
	if (ofile) fclose(ofile);
	free(buf2);
	free(buf1);
	return error;
}

static int
send_aspa_delta(int fd, uint8_t ver, serial_t oserial, serial_t nserial)
{
	FILE *ofile = NULL;
	FILE *nfile = NULL;
	unsigned char buf1[8];
	unsigned char buf2[8];
	unsigned char const *ochunk;
	unsigned char const *nchunk;
	struct aspa_providers oprovs;
	struct aspa_providers nprovs;
	int cmp;
	struct aspa aspa;
	int error;

	error = rtr_open_file(oserial, "aspa", "r", &ofile);
	if (error)
		return error;
	error = rtr_open_file(nserial, "aspa", "r", &nfile);
	if (error)
		goto end;

	ochunk = next_chunk(ofile, buf1, 8, &error);
	if (error)
		goto end;
	nchunk = next_chunk(nfile, buf2, 8, &error);
	if (error)
		goto end;

	while (ochunk && nchunk) {
		cmp = memcmp(ochunk, nchunk, 4); /* AS only */
		if (cmp < 0) {
			error = send_aspa_withdraw(fd, ver, ochunk, ofile);
			if (error)
				goto end;
			ochunk = next_chunk(ofile, buf1, 8, &error);
			if (error)
				goto end;
		} else if (cmp > 0) {
			error = send_aspa_announce(fd, ver, nchunk, nfile);
			if (error)
				goto end;
			nchunk = next_chunk(nfile, buf2, 8, &error);
			if (error)
				goto end;
		} else {
			error = parse_providers(ochunk, ofile, &oprovs);
			if (error)
				goto end;
			error = parse_providers(nchunk, nfile, &nprovs);
			if (error) {
				free(oprovs.asids);
				goto end;
			}

			if (!providers_equal(&oprovs, &nprovs)) {
				aspa.customer = read_u32(nchunk);
				aspa.providers = nprovs;
				error = send_aspa_announce_pdu(fd, ver, &aspa);
				if (error) {
					free(oprovs.asids);
					free(nprovs.asids);
					goto end;
				}
			}

			free(oprovs.asids);
			free(nprovs.asids);

			ochunk = next_chunk(ofile, buf1, 8, &error);
			if (error)
				goto end;
			nchunk = next_chunk(nfile, buf2, 8, &error);
			if (error)
				goto end;
		}
	}

	while (ochunk) {
		error = send_aspa_withdraw(fd, ver, ochunk, ofile);
		if (error)
			goto end;
		ochunk = next_chunk(ofile, buf1, 8, &error);
		if (error)
			goto end;
	}

	while (nchunk) {
		error = send_aspa_announce(fd, ver, nchunk, nfile);
		if (error)
			goto end;
		nchunk = next_chunk(nfile, buf2, 8, &error);
		if (error)
			goto end;
	}

end:	if (ofile) fclose(ofile);
	if (nfile) fclose(nfile);
	return error;
}

int
handle_serial_query_pdu(struct rtr_request *request)
{
	struct rtr_metadata rtr;
	serial_t oserial, nserial;
	struct rtr_stream stream;
	int error;

	pr_op_debug("Serial Query. Request version/session/serial: %u/%u/%u",
	    request->pdu.rtr_version,
	    request->pdu.obj.sq.session_id,
	    request->pdu.obj.sq.serial_number);

	stream.fd = request->fd;
	stream.ver = request->pdu.rtr_version;

	error = load_rtr_metadata(&rtr, stream.ver);
	switch (error) {
	case 0:      break;
	case ENOENT: return err_pdu_send_no_data_available(stream.fd, stream.ver);
	default:     goto internal_error;
	}

	if (request->pdu.obj.sq.session_id != rtr.session)
		return send_cache_reset_pdu(stream.fd, stream.ver);

	oserial = request->pdu.obj.sq.serial_number;
	nserial = rtr.serial;

	error = rtr_serial_stat(oserial);
	switch (error) {
	case 0:      break;
	case ENOENT: return send_cache_reset_pdu(stream.fd, stream.ver);
	default:     goto internal_error;
	}

	pr_op_debug("Sending RTR delta: %u-%u", oserial, nserial);

	error = send_cache_response_pdu(stream.fd, stream.ver, rtr.session);
	if (error)
		return error;

	stream.type = "vrp4";
	stream.rawlen = 10;
	stream.send = send_vrp4;
	error = send_delta(&stream, oserial, nserial);
	if (error)
		goto internal_error;

	stream.type = "vrp6";
	stream.rawlen = 22;
	stream.send = send_vrp6;
	error = send_delta(&stream, oserial, nserial);
	if (error)
		goto internal_error;

	if (stream.ver >= RTR_V1) {
		stream.type = "rk";
		stream.rawlen = 4 + RK_SKI_LEN + RK_SPKI_LEN;
		stream.send = send_rk;
		error = send_delta(&stream, oserial, nserial);
		if (error)
			goto internal_error;
	}

	if (stream.ver >= RTR_V2) {
		error = send_aspa_delta(stream.fd, stream.ver, oserial, nserial);
		if (error)
			goto internal_error;
	}

	return send_end_of_data_pdu(stream.fd, stream.ver, rtr.session, nserial);

internal_error:
	err_pdu_send_internal_error(stream.fd, stream.ver);
	return error;
}
