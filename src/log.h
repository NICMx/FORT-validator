#ifndef _SRC_LOG_H
#define _SRC_LOG_H


#include <stdio.h>
#define log_debug(text, ...) printf(text "\n", ##__VA_ARGS__)
#define log_info(text, ...) log_debug(text, ##__VA_ARGS__)
#define log_err(text, ...) fprintf(stderr, text "\n", ##__VA_ARGS__)
#define log_err0(text) fprintf(stderr, text "\n")



#endif /* _SRC_LOG_H */
