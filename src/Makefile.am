bin_PROGRAMS = rpki_validator

rpki_validator_SOURCES  = main.c
rpki_validator_SOURCES += common.h
rpki_validator_SOURCES += content_info.h content_info.c
rpki_validator_SOURCES += file.h file.c
rpki_validator_SOURCES += oid.h oid.c
rpki_validator_SOURCES += signed_data.h signed_data.c

rpki_validator_CFLAGS = -pedantic -Wall -std=gnu11 -O0 -g ${OPENSSL_CFLAGS}
rpki_validator_LDADD = ${OPENSSL_LIBS}
