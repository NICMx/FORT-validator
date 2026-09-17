#ifndef SRC_SIG_H_
#define SRC_SIG_H_

#include <stdbool.h>

extern volatile bool fort_end;

void register_signal_handlers(void);

#endif /* SRC_SIG_H_ */
