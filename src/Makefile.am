bin_PROGRAMS = fort fort-rtr
noinst_LTLIBRARIES = libfort.la

if BACKTRACE_ENABLED
CFLAGS_BT = -DBACKTRACE_ENABLED
LDFLAGS_BT = -rdynamic
endif

libfort_la_SOURCES = \
	common/alloc.c common/alloc.h \
	common/cache_rtr.c common/cache_rtr.h \
	common/common.c common/common.h \
	common/config.c common/config.h \
	common/config/boolean.c common/config/boolean.h \
	common/config/curl_offset.c common/config/curl_offset.h \
	common/config/file_type.c common/config/file_type.h \
	common/config/incidences.c common/config/incidences.h \
	common/config/log_conf.c common/config/log_conf.h \
	common/config/output_format.c common/config/output_format.h \
	common/config/str.c common/config/str.h \
	common/config/string_array.c common/config/string_array.h \
	common/config/time.c common/config/time.h \
	common/config/types.h \
	common/config/uint.c common/config/uint.h \
	common/daemon.c common/daemon.h \
	common/file.c common/file.h \
	common/log.c common/log.h \
	common/report.c common/report.h \
	common/types/address.c common/types/address.h \
	common/types/array.h \
	common/types/arraylist.h \
	common/types/asn.h \
	common/types/aspa.c common/types/aspa.h \
	common/types/bio_seq.c common/types/bio_seq.h \
	common/types/map.c common/types/map.h \
	common/types/name.c common/types/name.h \
	common/types/path.c common/types/path.h \
	common/types/router_key.c common/types/router_key.h \
	common/types/serial.c common/types/serial.h \
	common/types/sorted_array.c common/types/sorted_array.h \
	common/types/str.c common/types/str.h \
	common/types/uri.c common/types/uri.h \
	common/types/uthash.h \
	common/types/vrp.c common/types/vrp.h
libfort_la_CFLAGS = -Wall -Wpedantic -std=c99 -D_XOPEN_SOURCE=700 -O0 -g ${CFLAGS_BT}
libfort_la_LDFLAGS = ${LDFLAGS_BT}
libfort_la_LIBADD = ${JANSSON_LIBS}

include validator/asn1/asn1c/Makefile.include

fort_SOURCES = \
	validator/algorithm.c validator/algorithm.h \
	validator/asn1/content_info.c validator/asn1/content_info.h \
	validator/asn1/decode.c validator/asn1/decode.h \
	validator/asn1/oid.c validator/asn1/oid.h \
	validator/asn1/signed_data.c validator/asn1/signed_data.h \
	validator/base64.c validator/base64.h \
	validator/cache.c validator/cache.h \
	validator/cachefile.c validator/cachefile.h \
	validator/cachetmp.c validator/cachetmp.h \
	validator/config.c validator/config.h \
	validator/dao/rsync.c validator/dao/rsync.h \
	validator/dao/ta.c validator/dao/ta.h \
	validator/db/db_table.c validator/db/db_table.h \
	validator/db/vrps.c validator/db/vrps.h \
	validator/ext.c validator/ext.h \
	validator/hash.c validator/hash.h \
	validator/http.c validator/http.h \
	validator/json_handler.c validator/json_handler.h \
	validator/json_util.c validator/json_util.h \
	validator/libcrypto_util.c validator/libcrypto_util.h \
	validator/main.c \
	validator/nid.c validator/nid.h \
	validator/object/aspa.c validator/object/aspa.h \
	validator/object/certificate.c validator/object/certificate.h \
	validator/object/crl.c validator/object/crl.h \
	validator/object/ghostbusters.c validator/object/ghostbusters.h \
	validator/object/manifest.c validator/object/manifest.h \
	validator/object/roa.c validator/object/roa.h \
	validator/object/signed_object.c validator/object/signed_object.h \
	validator/object/tal.c validator/object/tal.h \
	validator/object/vcard.c validator/object/vcard.h \
	validator/output_printer.c validator/output_printer.h \
	validator/print_file.c validator/print_file.h \
	validator/prometheus.c validator/prometheus.h \
	validator/resource/asn.c validator/resource/asn.h \
	validator/resource.c validator/resource.h \
	validator/resource/ip4.c validator/resource/ip4.h \
	validator/resource/ip6.c validator/resource/ip6.h \
	validator/rrdp.c validator/rrdp.h \
	validator/rrdp_xml.c validator/rrdp_xml.h \
	validator/rsync.c validator/rsync.h \
	validator/sig.c validator/sig.h \
	validator/slurm/db_slurm.c validator/slurm/db_slurm.h \
	validator/slurm/slurm_loader.c validator/slurm/slurm_loader.h \
	validator/slurm/slurm_parser.c validator/slurm/slurm_parser.h \
	validator/stats.c validator/stats.h \
	validator/stream.c validator/stream.h \
	validator/task.c validator/task.h \
	validator/thread_var.c validator/thread_var.h \
	validator/types/rpp.c validator/types/rpp.h \
	validator/types/vthread.c validator/types/vthread.h \
	${ASN_MODULE_SRCS} ${ASN_MODULE_HDRS}
fort_CFLAGS = -Wall -Wpedantic -std=c99 -D_XOPEN_SOURCE=700 -O0 -g ${CFLAGS_BT}
fort_LDFLAGS = ${LDFLAGS_BT}
fort_LDADD = libfort.la ${JANSSON_LIBS} ${CURL_LIBS} ${MICROHTTPD_LIBS}

fort_rtr_SOURCES = \
	rtr/err_pdu.c rtr/err_pdu.h \
	rtr/main.c \
	rtr/pdu.c rtr/pdu.h \
	rtr/pdu_handler.c rtr/pdu_handler.h \
	rtr/pdu_sender.c rtr/pdu_sender.h \
	rtr/pdu_stream.c rtr/pdu_stream.h \
	rtr/primitive_writer.c rtr/primitive_writer.h
fort_rtr_CFLAGS = -Wall -Wpedantic -std=c99 -D_XOPEN_SOURCE=700 -O0 -g ${CFLAGS_BT}
fort_rtr_LDFLAGS = ${LDFLAGS_BT}
fort_rtr_LDADD = libfort.la ${JANSSON_LIBS}

GCC_WARNS  = -fmax-errors=1 -fanalyzer
GCC_WARNS += -pedantic-errors -Waddress -Walloc-zero -Walloca
GCC_WARNS += -Wno-aggressive-loop-optimizations -Warray-bounds=2 -Wbool-compare
GCC_WARNS += -Wbool-operation -Wno-builtin-declaration-mismatch -Wcast-align
GCC_WARNS += -Wcast-qual -Wchar-subscripts -Wclobbered -Wcomment
GCC_WARNS += -Wdangling-else -Wdate-time -Wdisabled-optimization
GCC_WARNS += -Wdouble-promotion -Wduplicated-branches -Wduplicated-cond
GCC_WARNS += -Wempty-body -Wenum-compare -Wexpansion-to-defined -Wfloat-equal
GCC_WARNS += -Wformat -Wformat-nonliteral -Wformat-overflow=2 -Wformat-security
GCC_WARNS += -Wformat-signedness -Wformat-truncation=2 -Wformat-y2k
GCC_WARNS += -Wframe-address -Wjump-misses-init -Wignored-qualifiers
GCC_WARNS += -Wignored-attributes -Wincompatible-pointer-types
GCC_WARNS += -Wimplicit-fallthrough
GCC_WARNS += -Wimplicit-function-declaration -Wimplicit-int -Winit-self -Winline
GCC_WARNS += -Wint-in-bool-context -Winvalid-memory-model -Winvalid-pch
GCC_WARNS += -Wlogical-op -Wlogical-not-parentheses -Wlong-long -Wmain
GCC_WARNS += -Wmaybe-uninitialized -Wmemset-elt-size -Wmemset-transposed-args
GCC_WARNS += -Wmisleading-indentation -Wmissing-braces -Wmissing-include-dirs
GCC_WARNS += -Wnonnull -Wnonnull-compare -Wnormalized -Wnull-dereference
# Seems undocumented
GCC_WARNS += -Wodr
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
GCC_WARNS += -Whsa
# Relatively arbitrary
GCC_WARNS += -Wlarger-than=2048 -Walloc-size-larger-than=4096
GCC_WARNS += -Wframe-larger-than=1024 -Wstack-usage=1024
# Can't use because of dependencies: -Waggregate-return
# Want to add, but need work: -Wconversion, -Wsign-compare, -Wsign-conversion
# Seem to require other compiler features: -Wchkp, -Wstack-protector,
#     -Wstrict-aliasing
