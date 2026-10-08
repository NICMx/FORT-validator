#ifndef VALIDATOR_CACHETMP_H_
#define VALIDATOR_CACHETMP_H_

#define CACHE_TMPDIR "tmp"
#define CACHE_TMPFILE_BUFLEN 24 /* tmp/%X\0 */

void cache_tmpfile(char *);	/* Return new unique path in <cache>/tmp/ */

#endif /* VALIDATOR_CACHETMP_H_ */
