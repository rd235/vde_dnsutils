/*   
 *   name_utils.c: name to string coversions 
 *   (asdescribed in section 3.1 and 4.1.4 of rfc 1035)
 *   
 *   Copyright 2017 Renzo Davoli - Virtual Square Team 
 *   University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#include <name_utils.h>
#define MAXNAME 256
/* get a DNS encoded (maybe compressed) name and store it in a string */
/* (buf is the packet buffer for compression. COmpression is not supported if buf is NULL) */
void getname(char *buf, char *curin, char *name, char *limit) {
	char *curout = name;
	while (*curin != 0 && curin < limit) {
		char len;
		if (curin[0] >> 6 == 3) {
			if (buf == 0)
				break;
			curin=buf+(((curin[0] & 0x3f) << 8) + curin[1]);
			continue;
		}
		for (len=*curin++; len>0 && curout-name < MAXNAME-1; len--)
			*curout++ = *curin++;
		if (curout-name < MAXNAME-1)
			*curout++ = '.';
	}
	*curout=0;
}

/* convert a name in DNS format (without compression):
	 host.domain.org. -> \004host\006domain\003org\000.
	 conversion is correct whether or not there is the final dot.
	 returns the length in byte of the converted string */
unsigned int name2dns(char *name, char *out) {
	unsigned int len=1;
	while (*name) {
		char *namelen=out++;
		//printf("name %s\n",name);
		while (*name!=0 && *name!='.')
			*out++=*name++;
		if (*name == '.') name++;
		*namelen=out-namelen-1;
		len+=(*namelen)+1;
		//printf("namelen %u\n",*namelen);
	}
	*out=0;
	return len;
}

char *skipname(char *s)
{
	//printf("skipname %s\n",s);
	if (*s==0) return s+1;
	if ((*s & 0xc0) == 0xc0) return s+2;
	return skipname(s+ (*s+1));
}

