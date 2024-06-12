#ifndef SRC_TYPES_STR_H_
#define SRC_TYPES_STR_H_

#include "data_structure/array_list.h"

DEFINE_ARRAY_LIST_STRUCT(strlist, char *);

void strlist_init(struct strlist *);
void strlist_cleanup(struct strlist *);
void strlist_add(struct strlist *list, char *elem);

#endif /* SRC_TYPES_STR_H_ */
