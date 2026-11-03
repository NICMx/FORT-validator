#ifndef SRC_TYPES_LIST_H_
#define SRC_TYPES_LIST_H_

#include <sys/queue.h>

#ifndef SLIST_FOREACH_SAFE
#define SLIST_FOREACH_SAFE(var, ls, lh, tmp)				\
    for (								\
        var = SLIST_FIRST(ls), tmp = (var ? SLIST_NEXT(var, lh) : NULL);\
        var != NULL;							\
        var = tmp, tmp = (var ? SLIST_NEXT(var, lh) : NULL)		\
    )
#endif

#ifndef LIST_FOREACH_SAFE
#define LIST_FOREACH_SAFE(var, ls, lh, tmp)				\
    for (								\
        var = LIST_FIRST(ls), tmp = (var ? LIST_NEXT(var, lh) : NULL);	\
        var != NULL;							\
        var = tmp, tmp = (var ? LIST_NEXT(var, lh) : NULL)		\
    )
#endif

#endif /* SRC_TYPES_LIST_H_ */
