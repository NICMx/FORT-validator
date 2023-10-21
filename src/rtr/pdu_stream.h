#ifndef SRC_RTR_PDU_STREAM_H_
#define SRC_RTR_PDU_STREAM_H_

#include "rtr/pdu.h"
#include "rtr/rtr.h"
#include "data_structure/array_list.h"

struct pdu_stream; /* It's an *input* stream. */

struct rtr_request {
	int fd;
	char client_addr[INET6_ADDRSTRLEN];

	struct {
		enum rtr_version rtr_version;
		enum pdu_type type;

		/* Deserialized version */
		union {
			struct {
				uint16_t session_id;
				uint32_t serial_number;
			} sq; /* Serial Query */
		} obj;

		/*
		 * Serialized version.
		 * Can be truncated; use for responding errors only.
		 */
		struct rtr_buffer raw;
	} pdu;

	bool eos; /* end of stream */
};

struct pdu_stream *pdustream_create(int, char const *);
void pdustream_destroy(struct pdu_stream **);

bool pdustream_next(struct pdu_stream *, struct rtr_request **);
int pdustream_fd(struct pdu_stream *);
char const *pdustream_addr(struct pdu_stream *);
int pdustream_version(struct pdu_stream *);

void rtreq_destroy(struct rtr_request *);

#endif /* SRC_RTR_PDU_STREAM_H_ */
