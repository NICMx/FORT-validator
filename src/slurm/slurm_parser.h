#ifndef SRC_SLURM_SLURM_PARSER_H_
#define SRC_SLURM_SLURM_PARSER_H_

#include "rtr/db/vrp.h"

/* Flags to get data from structs */
#define SLURM_COM_FLAG_NONE		0x00
#define SLURM_COM_FLAG_ASN		0x01
#define SLURM_COM_FLAG_COMMENT		0x02

#define SLURM_PFX_FLAG_PREFIX		0x04
#define SLURM_PFX_FLAG_MAX_LENGTH	0x08

#define SLURM_BGPS_FLAG_SKI		0x04
#define SLURM_BGPS_FLAG_ROUTER_KEY	0x08

struct slurm_prefix {
	uint8_t		data_flag;
	struct vrp	vrp;
	char 		*comment;
};

struct slurm_bgpsec {
	uint8_t		data_flag;
	uint32_t	asn;
	unsigned char	*ski;
	size_t		ski_len;
	unsigned char	*router_public_key;
	size_t		router_public_key_len;
	char 		*comment;
};


int slurm_parse(char const *, void *);


#endif /* SRC_SLURM_SLURM_PARSER_H_ */
