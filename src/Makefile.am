AM_CFLAGS = -pedantic -Wall -std=gnu11 -O3
AM_LDFLAGS = 

bin_PROGRAMS = rtr_server

rtr_server_SOURCES = main.c
rtr_server_SOURCES += address.c address.h
rtr_server_SOURCES += array_list.h
rtr_server_SOURCES += common.c common.h
rtr_server_SOURCES += configuration.c configuration.h
rtr_server_SOURCES += csv.c csv.h
rtr_server_SOURCES += line_file.c line_file.h
rtr_server_SOURCES += vrps.c vrps.h

rtr_server_SOURCES += rtr/pdu_handler.c rtr/pdu_handler.h
rtr_server_SOURCES += rtr/pdu.c rtr/pdu.h
rtr_server_SOURCES += rtr/primitive_reader.c rtr/primitive_reader.h
rtr_server_SOURCES += rtr/rtr.c rtr/rtr.h

rtr_server_LDADD = ${JANSSON_LIBS}