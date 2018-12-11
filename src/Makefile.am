# Comment these out during releases.
CFLAGS_DEBUG  = -DDEBUG
LDFLAGS_DEBUG = -rdynamic

bin_PROGRAMS = rpki_validator

rpki_validator_SOURCES  = main.c

rpki_validator_SOURCES += address.h address.c
rpki_validator_SOURCES += common.h common.c
rpki_validator_SOURCES += debug.h debug.c
rpki_validator_SOURCES += file.h file.c
rpki_validator_SOURCES += filename_stack.h filename_stack.c
rpki_validator_SOURCES += line_file.h line_file.c
rpki_validator_SOURCES += log.h log.c
rpki_validator_SOURCES += resource.h resource.c
rpki_validator_SOURCES += sorted_array.h sorted_array.c
rpki_validator_SOURCES += state.h state.c

rpki_validator_SOURCES += asn1/content_info.h asn1/content_info.c
rpki_validator_SOURCES += asn1/decode.h asn1/decode.c
rpki_validator_SOURCES += asn1/oid.h asn1/oid.c
rpki_validator_SOURCES += asn1/signed_data.h asn1/signed_data.c

rpki_validator_SOURCES += object/certificate.h object/certificate.c
rpki_validator_SOURCES += object/crl.h object/crl.c
rpki_validator_SOURCES += object/manifest.h object/manifest.c
rpki_validator_SOURCES += object/roa.h object/roa.c
rpki_validator_SOURCES += object/signed_object.h object/signed_object.c
rpki_validator_SOURCES += object/tal.h object/tal.c

rpki_validator_SOURCES += resource/ip4.h resource/ip4.c
rpki_validator_SOURCES += resource/ip6.h resource/ip6.c
rpki_validator_SOURCES += resource/asn.h resource/asn.c

rpki_validator_CFLAGS  = -pedantic -Wall -std=gnu11 -O0 -g $(CFLAGS_DEBUG)
rpki_validator_LDFLAGS = $(LDFLAGS_DEBUG)
