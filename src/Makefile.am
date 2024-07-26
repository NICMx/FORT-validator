bin_PROGRAMS = fort

fort_SOURCES = alloc.c alloc.h
fort_SOURCES += cache/cachent.c cache/cachent.h
fort_SOURCES += cache/local_cache.c cache/local_cache.h
fort_SOURCES += log.c log.h
fort_SOURCES += rsync/rsync.c rsync/rsync.h
fort_SOURCES += rrdp.c rrdp.h

fort_CFLAGS  = -Wall -Wpedantic -Werror
#fort_CFLAGS += $(GCC_WARNS)
fort_CFLAGS += -std=c99 -D_DEFAULT_SOURCE=1 -D_XOPEN_SOURCE=700 -D_BSD_SOURCE=1
fort_CFLAGS += -O2 -g $(FORT_FLAGS) ${XML2_CFLAGS}
if BACKTRACE_ENABLED
fort_CFLAGS += -DBACKTRACE_ENABLED
fort_LDFLAGS = -rdynamic
endif
fort_LDADD   = ${JANSSON_LIBS} ${CURL_LIBS} ${XML2_LIBS}

# I'm tired of scrolling up, but feel free to comment this out.
GCC_WARNS  = -fmax-errors=1

GCC_WARNS += -pedantic-errors -Waddress -Walloc-zero -Walloca
GCC_WARNS += -Wno-aggressive-loop-optimizations -Warray-bounds=2 -Wbool-compare
GCC_WARNS += -Wbool-operation -Wno-builtin-declaration-mismatch -Wcast-align
GCC_WARNS += -Wcast-qual -Wchar-subscripts -Wchkp -Wclobbered -Wcomment
GCC_WARNS += -Wdangling-else -Wdate-time -Wdisabled-optimization
GCC_WARNS += -Wdouble-promotion -Wduplicated-branches -Wduplicated-cond
GCC_WARNS += -Wempty-body -Wenum-compare -Wexpansion-to-defined -Wfloat-equal
GCC_WARNS += -Wformat -Wformat-nonliteral -Wformat-overflow=2 -Wformat-security
GCC_WARNS += -Wformat-signedness -Wformat-truncation=2 -Wformat-y2k
GCC_WARNS += -Wframe-address -Wjump-misses-init -Wignored-qualifiers
GCC_WARNS += -Wignored-attributes -Wincompatible-pointer-types

# This is a fun one. Write "/* fallthrough */" to prevent a warning whenever
# switch cases do not break.
GCC_WARNS += -Wimplicit-fallthrough

GCC_WARNS += -Wimplicit-function-declaration -Wimplicit-int -Winit-self -Winline
GCC_WARNS += -Wint-in-bool-context -Winvalid-memory-model -Winvalid-pch
GCC_WARNS += -Wlogical-op -Wlogical-not-parentheses -Wlong-long -Wmain
GCC_WARNS += -Wmaybe-uninitialized -Wmemset-elt-size -Wmemset-transposed-args
GCC_WARNS += -Wmisleading-indentation -Wmissing-braces -Wmissing-include-dirs
GCC_WARNS += -Wnonnull -Wnonnull-compare -Wnormalized -Wnull-dereference

# This one seems to be undocumented.
GCC_WARNS += -Wodr

# "Warn if the vectorizer cost model overrides the OpenMP or the Cilk Plus simd
# directive set by user."
# ... What?
GCC_WARNS += -Wopenmp-simd

GCC_WARNS += -Woverride-init-side-effects -Woverlength-strings -Wpacked
GCC_WARNS += -Wpacked-bitfield-compat -Wparentheses -Wpointer-arith
GCC_WARNS += -Wpointer-compare -Wredundant-decls -Wrestrict -Wreturn-type
GCC_WARNS += -Wsequence-point -Wshadow -Wshift-overflow=2 -Wshift-count-negative
GCC_WARNS += -Wshift-count-overflow -Wshift-negative-value -Wfloat-conversion
GCC_WARNS += -Wsizeof-pointer-memaccess -Wsizeof-array-argument
GCC_WARNS += -Wstack-protector -Wstrict-aliasing -Wstrict-overflow=5
GCC_WARNS += -Wstringop-overflow=4 -Wsuggest-final-types -Wsuggest-final-methods
GCC_WARNS += -Wmissing-format-attribute -Wswitch -Wswitch-bool -Wswitch-enum
GCC_WARNS += -Wswitch-unreachable -Wsync-nand -Wtautological-compare
GCC_WARNS += -Wtrampolines -Wtrigraphs -Wtype-limits -Wundef -Wuninitialized
GCC_WARNS += -Wunknown-pragmas -Wunsafe-loop-optimizations
GCC_WARNS += -Wunsuffixed-float-constants -Wunused -Wunused-function
GCC_WARNS += -Wunused-label -Wunused-local-typedefs -Wunused-macros
GCC_WARNS += -Wunused-value -Wunused-variable -Wunused-const-variable=2
GCC_WARNS += -Wunused-but-set-parameter -Wunused-but-set-variable
GCC_WARNS += -Wvariadic-macros -Wvector-operation-performance -Wvla
GCC_WARNS += -Wvolatile-register-var -Wwrite-strings

# "Issue a warning when HSAIL cannot be emitted for the compiled function or
# OpenMP construct."
# Uh-huh.
GCC_WARNS += -Whsa

# I don't mind too much increasing these.
# Just make sure that you know what you're doing.
GCC_WARNS += -Wlarger-than=2048 -Walloc-size-larger-than=4096
GCC_WARNS += -Wframe-larger-than=1024 -Wstack-usage=1024

# Can't use because of dependencies: -Waggregate-return
# Want to add, but needs work: -Wconversion, -Wsign-compare, -Wsign-conversion
# Seem to require other compiler features: -Wchkp, -Wstack-protector,
#     -Wstrict-aliasing
