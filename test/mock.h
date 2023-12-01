#ifndef TEST_MOCK_H_
#define TEST_MOCK_H_

#define MOCK(name, type, result, ...) \
    type name(__VA_ARGS__) { return result; }
#define MOCK_TRUE(name, ...) \
    MOCK(name, bool, true, __VA_ARGS__)
#define MOCK_FALSE(name, ...) \
    MOCK(name, bool, false, __VA_ARGS__)
#define MOCK_INT(name, result, ...) \
    MOCK(name, int, result, __VA_ARGS__)
#define MOCK_UINT(name, result, ...) \
    MOCK(name, unsigned int, result, __VA_ARGS__)
#define MOCK_NULL(name, type, ...) \
    MOCK(name, type, NULL, __VA_ARGS__)
#define MOCK_VOID(name, ...) \
    void name(__VA_ARGS__) {}

#define __MOCK_ABORT_MSG ck_abort_msg("%s() called.", __func__)

#define __MOCK_ABORT(name, type, result, ...) \
    type name(__VA_ARGS__) { __MOCK_ABORT_MSG; return result; }
#define MOCK_ABORT_INT(name, ...) \
    __MOCK_ABORT(name, int, 0, __VA_ARGS__)
#define MOCK_ABORT_ENUM(name, type, ...) \
    __MOCK_ABORT(name, enum type, 0, __VA_ARGS__)
#define MOCK_ABORT_PTR(name, type, ...) \
    __MOCK_ABORT(name, struct type *, NULL, __VA_ARGS__)
#define MOCK_ABORT_VOID(name, ...) \
    void name(__VA_ARGS__) { __MOCK_ABORT_MSG; }

#endif /* TEST_MOCK_H_ */
