/*   
 *   hashdns.c: HASH based DNS
 *   revdb: data structure to hold data for reverse resolution
 *   
 *   Copyright 2016 Renzo Davoli - Virtual Square Team 
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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

static unsigned int revttl=60 /*3600*/;
static unsigned int nrecords;
static unsigned int maxrecords= 32 /*32768*/;

struct revaddr {
	struct revaddr *next;
	struct in6_addr addr;
	time_t expire;
	char name[];
};

static struct revaddr *rah;

void ra_add(char *name, struct in6_addr *addr)
{
	struct revaddr *scan=rah;
	while (scan) {
		if (memcmp (&(scan->addr),addr,sizeof(* addr)) == 0) {
			scan->expire = time(NULL) + revttl;
			//printf("update %ld\n",scan->expire);
			return;
		}
		scan = scan->next;
	}
	if (nrecords < maxrecords) {
		struct revaddr *ra=malloc(sizeof(struct revaddr)+strlen(name)+1);
		ra->addr = *addr;
		ra->expire = time(NULL) + revttl;
		ra->next = rah;
		strcpy(ra->name,name);
		//printf("new %ld\n",ra->expire);
		nrecords++;
		rah = ra;
	}
}

char *ra_search(struct in6_addr *addr)
{
	struct revaddr *scan=rah;
	while (scan) {
		if (memcmp (&(scan->addr),addr,sizeof(* addr)) == 0)
			return scan->name;
		scan=scan->next;
	}
	return NULL;
}

void ra_clean(void)
{
	static time_t last;
	time_t now=time(NULL);
	if (now > last) {
		struct revaddr **prec=&rah;
		struct revaddr *scan;
		while (*prec) {
			scan=*prec;
			if (scan->expire < now) {
				*prec = scan->next;
				nrecords--;
				free(scan);
			} else
				prec = &(scan->next);
		}
		last=now;
	}
}

void ra_setttl(unsigned int ttl) {
	revttl = ttl;
}

unsigned int ra_gettl(void) {
	return revttl;
}
