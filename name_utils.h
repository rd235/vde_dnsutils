#ifndef NAME_UTILS_H
#define NAME_UTILS_H
#define MAXNAME 256
/* get a DNS encoded (maybe compressed) name and store it in a string */
/* (buf is the packet buffer for compression. COmpression is not supported if buf is NULL) */
void getname(char *buf, char *curin, char *name, char *limit);

/* convert a name in DNS format (without compression):
	 host.domain.org. -> \004host\006domain\003org\000.
	 conversion is correct whether or not there is the final dot.
	 returns the length in byte of the converted string */
unsigned int name2dns(char *name, char *out);

/* skip a name encded in DNS format */
char *skipname(char *s);

#endif
