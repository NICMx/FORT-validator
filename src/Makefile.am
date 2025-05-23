# Comment these out during releases.
# Also increase optimization I guess (-O0 -> -On)
LDFLAGS_DEBUG = -rdynamic

bin_PROGRAMS = fort

fort_SOURCES  = main.c

fort_SOURCES += as_number.h
fort_SOURCES += algorithm.h algorithm.c
fort_SOURCES += alloc.h alloc.c
fort_SOURCES += certificate_refs.h certificate_refs.c
fort_SOURCES += cert_stack.h cert_stack.c
fort_SOURCES += common.c common.h
fort_SOURCES += config.h config.c
fort_SOURCES += daemon.h daemon.c
fort_SOURCES += extension.h extension.c
fort_SOURCES += file.h file.c
fort_SOURCES += init.h init.c
fort_SOURCES += json_util.c json_util.h
fort_SOURCES += line_file.h line_file.c
fort_SOURCES += libcrypto_util.h libcrypto_util.c
fort_SOURCES += log.h log.c
fort_SOURCES += nid.h nid.c
fort_SOURCES += output_printer.h output_printer.c
fort_SOURCES += print_file.h print_file.c
fort_SOURCES += resource.h resource.c
fort_SOURCES += rpp.h rpp.c
fort_SOURCES += rrdp.h rrdp.c
fort_SOURCES += sorted_array.h sorted_array.c
fort_SOURCES += state.h state.c
fort_SOURCES += str_token.h str_token.c
fort_SOURCES += thread_var.h thread_var.c
fort_SOURCES += json_handler.h json_handler.c
fort_SOURCES += validation_handler.h validation_handler.c

fort_SOURCES += asn1/content_info.h asn1/content_info.c
fort_SOURCES += asn1/decode.h asn1/decode.c
fort_SOURCES += asn1/oid.h asn1/oid.c
fort_SOURCES += asn1/signed_data.h asn1/signed_data.c

fort_SOURCES += types/address.h types/address.c
fort_SOURCES += types/bio_seq.c types/bio_seq.h
fort_SOURCES += types/delta.c types/delta.h
fort_SOURCES += types/router_key.c types/router_key.h
fort_SOURCES += types/serial.h types/serial.c
fort_SOURCES += types/uri.h types/uri.c
fort_SOURCES += types/vrp.c types/vrp.h

fort_SOURCES += cache/local_cache.c cache/local_cache.h

fort_SOURCES += config/boolean.c config/boolean.h
fort_SOURCES += config/curl_offset.c config/curl_offset.h
fort_SOURCES += config/file_type.h config/file_type.c
fort_SOURCES += config/filename_format.h config/filename_format.c
fort_SOURCES += config/log_conf.h config/log_conf.c
fort_SOURCES += config/mode.c config/mode.h
fort_SOURCES += config/incidences.h config/incidences.c
fort_SOURCES += config/output_format.h config/output_format.c
fort_SOURCES += config/str.c config/str.h
fort_SOURCES += config/string_array.h config/string_array.c
fort_SOURCES += config/types.h
fort_SOURCES += config/uint.c config/uint.h
fort_SOURCES += config/work_offline.c config/work_offline.h

fort_SOURCES += crypto/base64.h crypto/base64.c
fort_SOURCES += crypto/hash.h crypto/hash.c

fort_SOURCES += data_structure/array_list.h
fort_SOURCES += data_structure/common.h
fort_SOURCES += data_structure/path_builder.h data_structure/path_builder.c
fort_SOURCES += data_structure/uthash.h

fort_SOURCES += http/http.h http/http.c

fort_SOURCES += incidence/incidence.h incidence/incidence.c

fort_SOURCES += object/bgpsec.h object/bgpsec.c
fort_SOURCES += object/certificate.h object/certificate.c
fort_SOURCES += object/crl.h object/crl.c
fort_SOURCES += object/ghostbusters.h object/ghostbusters.c
fort_SOURCES += object/manifest.h object/manifest.c
fort_SOURCES += object/name.h object/name.c
fort_SOURCES += object/roa.h object/roa.c
fort_SOURCES += object/signed_object.h object/signed_object.c
fort_SOURCES += object/tal.h object/tal.c
fort_SOURCES += object/vcard.h object/vcard.c

fort_SOURCES += resource/ip4.h resource/ip4.c
fort_SOURCES += resource/ip6.h resource/ip6.c
fort_SOURCES += resource/asn.h resource/asn.c

fort_SOURCES += rsync/rsync.h rsync/rsync.c

fort_SOURCES += rtr/pdu_stream.c rtr/pdu_stream.h
fort_SOURCES += rtr/err_pdu.c rtr/err_pdu.h
fort_SOURCES += rtr/pdu_handler.c rtr/pdu_handler.h
fort_SOURCES += rtr/pdu_sender.c rtr/pdu_sender.h
fort_SOURCES += rtr/pdu.c rtr/pdu.h
fort_SOURCES += rtr/primitive_writer.c rtr/primitive_writer.h
fort_SOURCES += rtr/rtr.c rtr/rtr.h

fort_SOURCES += rtr/db/db_table.c rtr/db/db_table.h
fort_SOURCES += rtr/db/delta.c rtr/db/delta.h
fort_SOURCES += rtr/db/deltas_array.c rtr/db/deltas_array.h
fort_SOURCES += rtr/db/vrps.c rtr/db/vrps.h

fort_SOURCES += slurm/db_slurm.c slurm/db_slurm.h
fort_SOURCES += slurm/slurm_loader.c slurm/slurm_loader.h
fort_SOURCES += slurm/slurm_parser.c slurm/slurm_parser.h

fort_SOURCES += thread/thread_pool.c thread/thread_pool.h

fort_SOURCES += xml/relax_ng.c xml/relax_ng.h

include asn1/asn1c/Makefile.include
fort_SOURCES += $(ASN_MODULE_SRCS) $(ASN_MODULE_HDRS)

fort_CFLAGS  = -Wall -Wpedantic
#fort_CFLAGS += $(GCC_WARNS)
fort_CFLAGS += -std=c99 -D_DEFAULT_SOURCE=1 -D_XOPEN_SOURCE=700 -D_BSD_SOURCE=1
fort_CFLAGS += -O2 -g $(FORT_FLAGS) ${XML2_CFLAGS}
if BACKTRACE_ENABLED
fort_CFLAGS += -DBACKTRACE_ENABLED
endif
fort_LDFLAGS = $(LDFLAGS_DEBUG)
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
