# Comment these out during releases.
# Also increase optimization I guess (-O0 -> -On)
CFLAGS_DEBUG  = -DDEBUG
LDFLAGS_DEBUG = -rdynamic

bin_PROGRAMS = rpki_validator

rpki_validator_SOURCES  = main.c

rpki_validator_SOURCES += address.h address.c
rpki_validator_SOURCES += algorithm.h algorithm.c
rpki_validator_SOURCES += array_list.h
rpki_validator_SOURCES += certificate_refs.h certificate_refs.c
rpki_validator_SOURCES += common.h
rpki_validator_SOURCES += config.h config.c
rpki_validator_SOURCES += debug.h debug.c
rpki_validator_SOURCES += extension.h extension.c
rpki_validator_SOURCES += file.h file.c
rpki_validator_SOURCES += line_file.h line_file.c
rpki_validator_SOURCES += log.h log.c
rpki_validator_SOURCES += nid.h nid.c
rpki_validator_SOURCES += random.h random.c
rpki_validator_SOURCES += resource.h resource.c
rpki_validator_SOURCES += rpp.h rpp.c
rpki_validator_SOURCES += sorted_array.h sorted_array.c
rpki_validator_SOURCES += state.h state.c
rpki_validator_SOURCES += str.h str.c
rpki_validator_SOURCES += thread_var.h thread_var.c
rpki_validator_SOURCES += uri.h uri.c
rpki_validator_SOURCES += toml_handler.h toml_handler.c

rpki_validator_SOURCES += rsync/rsync.h rsync/rsync.c

rpki_validator_SOURCES += asn1/content_info.h asn1/content_info.c
rpki_validator_SOURCES += asn1/decode.h asn1/decode.c
rpki_validator_SOURCES += asn1/oid.h asn1/oid.c
rpki_validator_SOURCES += asn1/signed_data.h asn1/signed_data.c

rpki_validator_SOURCES += crypto/base64.h crypto/base64.c
rpki_validator_SOURCES += crypto/hash.h crypto/hash.c

rpki_validator_SOURCES += object/certificate.h object/certificate.c
rpki_validator_SOURCES += object/crl.h object/crl.c
rpki_validator_SOURCES += object/ghostbusters.h object/ghostbusters.c
rpki_validator_SOURCES += object/manifest.h object/manifest.c
rpki_validator_SOURCES += object/name.h object/name.c
rpki_validator_SOURCES += object/roa.h object/roa.c
rpki_validator_SOURCES += object/signed_object.h object/signed_object.c
rpki_validator_SOURCES += object/tal.h object/tal.c
rpki_validator_SOURCES += object/vcard.h object/vcard.c

rpki_validator_SOURCES += resource/ip4.h resource/ip4.c
rpki_validator_SOURCES += resource/ip6.h resource/ip6.c
rpki_validator_SOURCES += resource/asn.h resource/asn.c

rpki_validator_CFLAGS  = -Wall
# Feel free to temporarily remove this one if you're not using gcc 7.3.0.
rpki_validator_CFLAGS += $(GCC_WARNS)
rpki_validator_CFLAGS += -std=gnu99 -O0 -g $(CFLAGS_DEBUG)
rpki_validator_LDFLAGS = $(LDFLAGS_DEBUG)

# I'm tired of scrolling up, but feel free to comment this out.
GCC_WARNS  = -fmax-errors=1

# Please ready some arguments if you want to permanently remove some of these
# flags. I gave a quick read to the documentation of all of these warnings, and
# generally liked each of them.
GCC_WARNS += -Wpedantic -pedantic-errors -Waddress -Walloc-zero -Walloca
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
GCC_WARNS += -Wlarger-than=1024 -Walloc-size-larger-than=4096
GCC_WARNS += -Wframe-larger-than=1024 -Wstack-usage=1024

# Can't use because of dependencies: -Waggregate-return
# Want to add, but needs work: -Wconversion, -Wsign-compare, -Wsign-conversion
# Seem to require other compiler features: -Wchkp, -Wstack-protector,
#     -Wstrict-aliasing, -Wstrict-overflow
