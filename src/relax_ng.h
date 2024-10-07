#ifndef SRC_XML_RELAX_NG_H_
#define SRC_XML_RELAX_NG_H_

#include <libxml/xmlreader.h>

/*
 * Schema obtained from RFC 8182, converted using the tool rnc2rng
 * (https://github.com/djc/rnc2rng)
 */
#define RRDP_V1_RNG							\
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"				\
"<grammar xmlns=\"http://relaxng.org/ns/structure/1.0\""		\
"         ns=\"http://www.ripe.net/rpki/rrdp\""				\
"         datatypeLibrary=\"http://www.w3.org/2001/XMLSchema-datatypes\">"\
"  <define name=\"version\">"						\
"    <data type=\"positiveInteger\">"					\
"      <param name=\"maxInclusive\">1</param>"				\
"    </data>"								\
"  </define>"								\
"  <define name=\"serial\">"						\
"    <data type=\"positiveInteger\"/>"					\
"  </define>"								\
"  <define name=\"uri\">"						\
"    <data type=\"anyURI\"/>"						\
"  </define>"								\
"  <define name=\"uuid\">"						\
"    <data type=\"string\">"						\
"      <param name=\"pattern\">[\\-0-9a-fA-F]+</param>"			\
"    </data>"								\
"  </define>"								\
"  <define name=\"hash\">"						\
"    <data type=\"string\">"						\
"      <param name=\"pattern\">[0-9a-fA-F]+</param>"			\
"    </data>"								\
"  </define>"								\
"  <define name=\"base64\">"						\
"    <data type=\"base64Binary\"/>"					\
"  </define>"								\
"  <start combine=\"choice\">"						\
"    <element>"								\
"      <name ns=\"http://www.ripe.net/rpki/rrdp\">notification</name>"	\
"      <attribute>"							\
"        <name ns=\"\">version</name>"					\
"        <ref name=\"version\"/>"					\
"      </attribute>"							\
"      <attribute>"							\
"        <name ns=\"\">session_id</name>"				\
"        <ref name=\"uuid\"/>"						\
"      </attribute>"							\
"      <attribute>"							\
"        <name ns=\"\">serial</name>"					\
"        <ref name=\"serial\"/>"					\
"      </attribute>"							\
"      <element>"							\
"        <name ns=\"http://www.ripe.net/rpki/rrdp\">snapshot</name>"	\
"        <attribute>"							\
"          <name ns=\"\">uri</name>"					\
"          <ref name=\"uri\"/>"						\
"        </attribute>"							\
"        <attribute>"							\
"          <name ns=\"\">hash</name>"					\
"          <ref name=\"hash\"/>"					\
"        </attribute>"							\
"      </element>"							\
"      <zeroOrMore>"							\
"        <element>"							\
"          <name ns=\"http://www.ripe.net/rpki/rrdp\">delta</name>"	\
"          <attribute>"							\
"            <name ns=\"\">serial</name>"				\
"            <ref name=\"serial\"/>"					\
"          </attribute>"						\
"          <attribute>"							\
"            <name ns=\"\">uri</name>"					\
"            <ref name=\"uri\"/>"					\
"          </attribute>"						\
"          <attribute>"							\
"            <name ns=\"\">hash</name>"					\
"            <ref name=\"hash\"/>"					\
"          </attribute>"						\
"        </element>"							\
"      </zeroOrMore>"							\
"    </element>"							\
"  </start>"								\
"  <start combine=\"choice\">"						\
"    <element>"								\
"      <name ns=\"http://www.ripe.net/rpki/rrdp\">snapshot</name>"	\
"      <attribute>"							\
"        <name ns=\"\">version</name>"					\
"        <ref name=\"version\"/>"					\
"      </attribute>"							\
"      <attribute>"							\
"        <name ns=\"\">session_id</name>"				\
"        <ref name=\"uuid\"/>"						\
"      </attribute>"							\
"      <attribute>"							\
"        <name ns=\"\">serial</name>"					\
"        <ref name=\"serial\"/>"					\
"      </attribute>"							\
"      <zeroOrMore>"							\
"        <element>"							\
"          <name ns=\"http://www.ripe.net/rpki/rrdp\">publish</name>"	\
"          <attribute>"							\
"            <name ns=\"\">uri</name>"					\
"            <ref name=\"uri\"/>"					\
"          </attribute>"						\
"          <ref name=\"base64\"/>"					\
"        </element>"							\
"      </zeroOrMore>"							\
"    </element>"							\
"  </start>"								\
"  <start combine=\"choice\">"						\
"    <element>"								\
"      <name ns=\"http://www.ripe.net/rpki/rrdp\">delta</name>"		\
"      <attribute>"							\
"        <name ns=\"\">version</name>"					\
"        <ref name=\"version\"/>"					\
"      </attribute>"							\
"      <attribute>"							\
"        <name ns=\"\">session_id</name>"				\
"        <ref name=\"uuid\"/>"						\
"      </attribute>"							\
"      <attribute>"							\
"        <name ns=\"\">serial</name>"					\
"        <ref name=\"serial\"/>"					\
"      </attribute>"							\
"      <oneOrMore>"							\
"        <ref name=\"delta_element\"/>"					\
"      </oneOrMore>"							\
"    </element>"							\
"  </start>"								\
"  <define name=\"delta_element\" combine=\"choice\">"			\
"    <element>"								\
"      <name ns=\"http://www.ripe.net/rpki/rrdp\">publish</name>"	\
"      <attribute>"							\
"        <name ns=\"\">uri</name>"					\
"        <ref name=\"uri\"/>"						\
"      </attribute>"							\
"      <optional>"							\
"        <attribute>"							\
"          <name ns=\"\">hash</name>"					\
"          <ref name=\"hash\"/>"					\
"        </attribute>"							\
"      </optional>"							\
"      <ref name=\"base64\"/>"						\
"    </element>"							\
"  </define>"								\
"  <define name=\"delta_element\" combine=\"choice\">"			\
"    <element>"								\
"      <name ns=\"http://www.ripe.net/rpki/rrdp\">withdraw</name>"	\
"      <attribute>"							\
"        <name ns=\"\">uri</name>"					\
"        <ref name=\"uri\"/>"						\
"      </attribute>"							\
"      <attribute>"							\
"        <name ns=\"\">hash</name>"					\
"        <ref name=\"hash\"/>"						\
"      </attribute>"							\
"    </element>"							\
"  </define>"								\
"</grammar>"


int relax_ng_init(void);
void relax_ng_cleanup(void);

typedef int (*xml_read_cb)(xmlTextReaderPtr, void *);
int relax_ng_parse(const char *, xml_read_cb cb, void *);

#endif /* SRC_XML_RELAX_NG_H_ */
