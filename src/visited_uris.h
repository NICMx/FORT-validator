#ifndef SRC_VISITED_URIS_H_
#define SRC_VISITED_URIS_H_

#include <stdbool.h>

struct visited_uris;

int visited_uris_create(struct visited_uris **);
void visited_uris_refput(struct visited_uris *);
void visited_uris_refget(struct visited_uris *);

int visited_uris_add(struct visited_uris *, char const *);
int visited_uris_remove(struct visited_uris *, char const *);
bool visited_uris_exists(struct visited_uris *, char const *);
int visited_uris_get_root(struct visited_uris *, char **);

#endif /* SRC_VISITED_URIS_H_ */
