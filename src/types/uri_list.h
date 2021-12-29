#ifndef SRC_TYPES_URI_LIST_H_
#define SRC_TYPES_URI_LIST_H_

#include "types/uri.h"
#include "data_structure/array_list.h"

DEFINE_ARRAY_LIST_STRUCT(uri_list, struct rpki_uri *);

void uris_init(struct uri_list *);
void uris_cleanup(struct uri_list *);

int uris_add(struct uri_list *, struct rpki_uri *);
int uris_add_str(struct uri_list *uri, char *str, enum rpki_uri_type type);

bool uris_contains(struct uri_list *, struct rpki_uri *);
struct rpki_uri *uris_download(struct uri_list *);

#endif /* SRC_TYPES_URI_LIST_H_ */
