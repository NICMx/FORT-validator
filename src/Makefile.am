bin_PROGRAMS = rpki_validator

rpki_validator_SOURCES  = main.c
rpki_validator_SOURCES += common.h
rpki_validator_SOURCES += line_file.h
rpki_validator_SOURCES += line_file.c
rpki_validator_SOURCES += tal.h
rpki_validator_SOURCES += tal.c

rpki_validator_CFLAGS = -pedantic -Wall -std=gnu11 -O3 ${GLIB_CFLAGS}
rpki_validator_LDADD = ${GLIB_LIBS}
