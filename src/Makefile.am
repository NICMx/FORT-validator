bin_PROGRAMS = rpki_validator

rpki_validator_SOURCES  = main.c

rpki_validator_SOURCES += common.h
rpki_validator_SOURCES += file.h file.c
rpki_validator_SOURCES += asn1/content_info.h asn1/content_info.c
rpki_validator_SOURCES += asn1/decode.h asn1/decode.c
rpki_validator_SOURCES += asn1/oid.h asn1/oid.c
rpki_validator_SOURCES += asn1/roa.h asn1/roa.c
rpki_validator_SOURCES += asn1/signed_data.h asn1/signed_data.c

rpki_validator_CFLAGS = -pedantic -Wall -std=gnu11 -O0 -g ${OPENSSL_CFLAGS}
rpki_validator_LDADD = ${OPENSSL_LIBS}
