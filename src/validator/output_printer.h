#ifndef VALIDATOR_OUTPUT_PRINTER_H_
#define VALIDATOR_OUTPUT_PRINTER_H_

#include "validator/db/db_table.h"

int output_setup(void);
void output_print_data(struct db_table const *);
void output_atexit(void);

#endif /* VALIDATOR_OUTPUT_PRINTER_H_ */
