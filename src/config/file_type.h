#ifndef SRC_CONFIG_FILE_TYPE_H_
#define SRC_CONFIG_FILE_TYPE_H_

#include "config/types.h"

enum file_type {
	FT_UNK,
	FT_ROA,
	FT_MFT,
	FT_GBR,
	FT_CER,
	FT_CRL,
};

extern const struct global_type gt_file_type;

#endif /* SRC_CONFIG_FILE_TYPE_H_ */
