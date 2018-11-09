AM_CFLAGS = -pedantic -Wall -std=gnu11 -O3
AM_LDFLAGS = 

bin_PROGRAMS = rtr_server

rtr_server_SOURCES = main.c
rtr_server_SOURCES += common.h
rtr_server_SOURCES += rtr/pdu.c
rtr_server_SOURCES += rtr/pdu.h
rtr_server_SOURCES += rtr/pdu_handler.c
rtr_server_SOURCES += rtr/pdu_handler.h
rtr_server_SOURCES += rtr/primitive_reader.c
rtr_server_SOURCES += rtr/primitive_reader.h
rtr_server_SOURCES += rtr/rtr.c
rtr_server_SOURCES += rtr/rtr.h
rtr_server_SOURCES += log.h
rtr_server_SOURCES += file.c
rtr_server_SOURCES += file.h
rtr_server_SOURCES += types.h
rtr_server_SOURCES += configuration.c
rtr_server_SOURCES += configuration.h
rtr_server_SOURCES += str_utils.c
rtr_server_SOURCES += str_utils.h

rtr_server_LDADD = ${JANSSON_LIBS}