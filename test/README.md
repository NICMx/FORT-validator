# Introduction

I decided to use the [Check Framework](https://libcheck.github.io/check/) for
unit testing.

This is how I understand it:

- Each `main()` has one or more "Suite"s.
- Each "Suite" has multiple "Test Case"s.
  "Test Case" is an odd name. They should be called "Test Type"s in my
  opinion. In the examples, one "test case" is "Core" (happy path tests),
  another one is "Limits" (the corner cases), and I imagine that one can add
  "Errors" and "Performance" and whatever.
- Each "Test Case" has multiple "test"s. Each "test" is a `_test` function.
  (Defined by `START_TEST` and `END_TEST`.)
- Each "test" is allowed to contain more than one function call, but it should
  normally only throw one kind of challenge to the target function.

The framework seems to want each suite to test one module, but in my opinion,
that's autotools's job. (Each `check_PROGRAM` in `Makefile.am` should test one
module, otherwise why the F would it allow multiple entries.) So I guess the
rule of thumb is as follows:

	Each "Suite" should test one (and only one) function within a module.

So then, each entry in `Makefile.am` is a module (within `/test/`) that tests
another module (within `/src/`). (If the name of the tested module is `A.c`, then
the name of the testing module is `A_test.c`.) Each testing module has one suite
per function within the tested module. Each suite has one test suite per test
type. And so on.

Testing private functions is totally allowed. Simply `#include` the `.c` (not the
`.h`) to do this.

# Running

The following commands are preparatory and only need to be run the first time,
_in the current directory's parent_:

	./autogen.sh
	./configure

Then, whenever you want to run the tests, enter the current directory and run

	make check

There's at least one very long test that lasts about a full minute.
