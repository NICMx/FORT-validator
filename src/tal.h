#ifndef TAL_H_
#define TAL_H_

struct tal;

int tal_load(const char *, struct tal **);
void tal_destroy(struct tal *);

#endif /* TAL_H_ */
