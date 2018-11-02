bin_PROGRAMS = rpki_validator

rpki_validator_SOURCES  = main2.c

rpki_validator_SOURCES += certificate.h certificate.c
rpki_validator_SOURCES += common.h common.c
rpki_validator_SOURCES += debug.h debug.c
rpki_validator_SOURCES += file.h file.c
rpki_validator_SOURCES += line_file.h line_file.c
rpki_validator_SOURCES += manifest.h manifest.c
rpki_validator_SOURCES += tal.h tal.c
rpki_validator_SOURCES += asn1/content_info.h asn1/content_info.c
rpki_validator_SOURCES += asn1/decode.h asn1/decode.c
rpki_validator_SOURCES += asn1/manifest.h asn1/manifest.c
rpki_validator_SOURCES += asn1/oid.h asn1/oid.c
rpki_validator_SOURCES += asn1/roa.h asn1/roa.c
rpki_validator_SOURCES += asn1/signed_data.h asn1/signed_data.c

rpki_validator_CFLAGS = -pedantic -Wall -std=gnu11 -O0 -g
# Remove -rdynamic during the release.
rpki_validator_LDFLAGS = -rdynamic
