#ifndef SRC_OUTPUT_PRINTER_H_
#define SRC_OUTPUT_PRINTER_H_

#include "rtr/db/db_table.h"

int output_setup(void);
void output_print_data(struct db_table const *);
void output_atexit(void);

#endif /* SRC_OUTPUT_PRINTER_H_ */
