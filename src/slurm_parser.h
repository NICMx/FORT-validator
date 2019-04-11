#ifndef SRC_SLURM_PARSER_H_
#define SRC_SLURM_PARSER_H_

/* Flags to get data from structs */
#define SLURM_COM_FLAG_NONE		0x00
#define SLURM_COM_FLAG_ASN		0x01
#define SLURM_COM_FLAG_COMMENT		0x02

#define SLURM_PFX_FLAG_PREFIX		0x04
#define SLURM_PFX_FLAG_MAX_LENGTH	0x08

#define SLURM_BGPS_FLAG_SKI		0x04
#define SLURM_BGPS_FLAG_ROUTER_KEY	0x08


int slurm_load(void);
void slurm_cleanup(void);

#endif /* SRC_SLURM_PARSER_H_ */
