#ifndef TEST_RRDP_UTIL_H_
#define TEST_RRDP_UTIL_H_

#define NHDR(serial) "<notification "					\
		"xmlns=\"http://www.ripe.net/rpki/rrdp\" "		\
		"version=\"1\" "					\
		"session_id=\"9df4b597-af9e-4dca-bdda-719cce2c4e28\" "	\
		"serial=\"" serial "\">\n"
#define NSS(u, h) "\t<snapshot uri=\"" u "\" hash=\"" h "\"/>\n"
#define NTAIL "</notification>"

#define SHDR(serial) "<snapshot "					\
		"xmlns=\"http://www.ripe.net/rpki/rrdp\" "		\
		"version=\"1\" "					\
		"session_id=\"9df4b597-af9e-4dca-bdda-719cce2c4e28\" "	\
		"serial=\"" serial "\">\n"
#define STAIL "</snapshot>"

#define PBLSH(u, c) "<publish uri=\"" u "\">" c "</publish>"

#endif /* TEST_RRDP_UTIL_H_ */
