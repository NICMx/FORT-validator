#ifndef SRC_FILENAME_STACK_H_
#define SRC_FILENAME_STACK_H_

void fnstack_init(void);
void fnstack_store(void);

void fnstack_push(char const *);
char const *fnstack_peek(void);
void fnstack_pop(void);

#endif /* SRC_FILENAME_STACK_H_ */
