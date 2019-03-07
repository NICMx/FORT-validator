#ifndef SRC_CONFIG_FILENAME_FORMAT_H_
#define SRC_CONFIG_FILENAME_FORMAT_H_

#include "config/types.h"

enum filename_format {
	/** Example: "rsync://repository.lacnic.net/rpki/foo/bar/baz.cer" */
	FNF_GLOBAL,
	/** Example: "/tmp/repo/repository.lacnic.net/rpki/foo/bar/baz.cer" */
	FNF_LOCAL,
	/** Example: "baz.cer" */
	FNF_NAME,
};

extern const struct global_type gt_filename_format;

#endif /* SRC_CONFIG_FILENAME_FORMAT_H_ */
