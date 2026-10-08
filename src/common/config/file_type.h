#ifndef COMMON_CONFIG_FILE_TYPE_H_
#define COMMON_CONFIG_FILE_TYPE_H_

#include "common/config/types.h"

enum file_type {
	FT_UNK,
	FT_ROA,
	FT_ASA,
	FT_MFT,
	FT_GBR,
	FT_CER,
	FT_CRL,
};

extern const struct global_type gt_file_type;

#endif /* COMMON_CONFIG_FILE_TYPE_H_ */
