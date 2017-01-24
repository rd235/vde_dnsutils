/*   
 *   hashdns.c: HASH based DNS
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
#include <signal.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <resolv.h>
#include <getbaseaddr.h>
extern int verbose;
static char *mapfile;
static char *mapdomain;

#define MAPQ_HOST 0
#define MAPQ_NET 1

static char *mapq_type_str[] = {"HOST", "NET"};

struct mapq {
	int type;
	char *domain;
	char *addr;
	struct mapq *next;
};
static struct mapq *mapqh;

static void printmapq(struct mapq *head) {
	if (head) {
		printf("%-4s DOMAIN=%s ADDR=%s\n",
				mapq_type_str[head->type],
				head->domain,head->addr);
		printmapq(head->next);
	}
}

static void sig_reloadmapfile();
int load_mapfile(void) {
	if (mapfile) {
		FILE *f=fopen(mapfile,"r");
		if (f) {
			char *line=NULL;
			size_t linesize=0;
			ssize_t linelen;
			struct mapq **mapq_next = &mapqh;
			while (mapqh) {
				struct mapq *this=mapqh;
				mapqh=this->next;
				free(this->domain);
				free(this->addr);
				free(this);
			}
			while((linelen=getline(&line,&linesize,f)) > 0) {
				char *domain,*addr,*type;
				domain=addr=type=NULL;
				//printf("%ld %s",linelen,line);
				sscanf(line,"%ms %ms %ms", &domain, &addr, &type);
				//printf("%p %p %p\n",domain, addr, type);
				if (domain && addr && *domain != '#') {
					struct mapq *new;
					if (domain[strlen(domain)-1] == '.')
						domain[strlen(domain)-1] = 0;
					new = *mapq_next = malloc(sizeof(struct mapq));
					if (new) {
						new->type = MAPQ_NET;
						new->domain=domain;
						new->addr=addr;
						if (type && strcmp(type, "host") == 0)
							new->type = MAPQ_HOST;
						new->next=NULL;
						mapq_next = & new->next;
					}
				} else {
					if (domain) free(domain);
					if (addr) free(addr);
				}
				if (type) free(type);
			}
			if (verbose) {
				printf("Load file map from %s\n",mapfile);
				printmapq(mapqh);
			}
			if (line) free(line);
			fclose(f);
			return 0;
		} else 
			return -1;
		sig_reloadmapfile();
	}
	return 0;
}


void hup_handler(int signal) {
	load_mapfile();
}

static void sig_reloadmapfile()
{
	struct sigaction act;
	memset(&act, 0, sizeof(act));

	act.sa_handler = hup_handler;       
	act.sa_flags    = 0;

	sigfillset(&(act.sa_mask));      

	sigaction(SIGHUP, &act, NULL);
}

int getbaseaddr_mapfile(struct in6_addr *baseaddr, char *name) {
	struct mapq *scan;
	size_t namelen=strlen(name);
	if (mapfile) {
		sigset_t hupset;
		sigset_t oldmask;
		sigemptyset(&hupset);
		sigaddset(&hupset, SIGHUP);
		/* disable file reload during scan */
		sigprocmask(SIG_BLOCK, &hupset, &oldmask);
		for (scan=mapqh; scan; scan=scan->next) {
			size_t domlen=strlen(scan->domain);
			 // printf("%s %s %ld %ld\n",name,scan->domain,namelen,domlen);
			if (namelen > domlen) {
				char *nametail=name+(namelen-domlen-1);
				 // printf("tail = %s\n",nametail);
				if (strncmp(scan->domain, name+(namelen-domlen-1), domlen) == 0 &&
						(nametail == name || (scan->type == MAPQ_NET && nametail[-1]=='.'))) {
					 // printf("Trying %s\n",scan->addr);
					switch (getaaaa(scan->addr, (char *) baseaddr)) {
						case 1:
							// printf("  got file match: %s %s\n",scan->domain,scan->addr);
							sigprocmask(SIG_SETMASK, &oldmask, NULL);
							return nametail==name ? 2 : 1;
						case -1:
							return 0;
					}
				}
			}
		}
		sigprocmask(SIG_SETMASK, &oldmask, NULL);
	}
	return 0;
}

int getbaseaddr_mapdomain(struct in6_addr *baseaddr, char *name) {
	if (mapdomain) {
		int mdlen=strlen(mapdomain);	
		int ucopylen=strlen(name)+strlen(mapdomain)+2;
		char ucopy[ucopylen];
		snprintf(ucopy, ucopylen, "%s%s", name, mapdomain);
		for (name=ucopy; strlen(name) > mdlen; name=strchr(name,'.')+1)
		{	
			switch (getaaaa(name, (char *) baseaddr)) {
				case 1:
					return name==ucopy ? 2 : 1;
				case -1:
					return 0;
			}
		}
	}
	return 0;
}

void getbaseaddr_setmapfile(char *path) {
	mapfile=path;
}

char *getbaseaddr_getmapfile(void) {
	return mapfile;
}

void getbaseaddr_setmapdomain(char *domain) {
	mapdomain=domain;
}
