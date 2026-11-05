#ifndef SRC_OUTPUT_PRINTER_H_
#define SRC_OUTPUT_PRINTER_H_

#include "rtr/db/vpt.h"

int output_setup(void);
void output_print_data(struct vp_table const *);
void output_atexit(void);

#endif /* SRC_OUTPUT_PRINTER_H_ */
