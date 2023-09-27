#ifndef LINE_FILE_H_
#define LINE_FILE_H_

/*
 * A "line file" is a text file that you want to read line-by-line.
 *
 * Lines are terminated by either CRLF or LF.
 * (...which is the same as saying "lines are terminated by LF.")
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

struct line_file;

int lfile_open(const char *, struct line_file **);
void lfile_close(struct line_file *lf);

int lfile_read(struct line_file *, char **);

FILE *lfile_fd(struct line_file *);
const char *lfile_name(struct line_file *);
size_t lfile_offset(struct line_file *);

#endif /* LINE_FILE_H_ */
