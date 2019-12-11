#ifndef SRC_VISITED_URIS_H_
#define SRC_VISITED_URIS_H_

#include <stdbool.h>

int visited_uris_init(void);
void visited_uris_destroy(void);

int visited_uris_add(char const *);
int visited_uris_remove(char const *);
bool visited_uris_exists(char const *);

#endif /* SRC_VISITED_URIS_H_ */
