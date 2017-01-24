#ifndef GETBASEADDR_H
#define GETBASEADDR_H

/* load the map file and set up SIGHUP handler to reload it */
int load_mapfile(void); 

/* get a map using the file */
/* it returns 0 if no match, 1 if partial match, 2 if total match */
int getbaseaddr_mapfile(struct in6_addr *baseaddr, char *name);

/* get a map using the domain def:
trying to resolve host.sub.hash.domain.org, if mapdomain is map.domain.org it tries to get
a base addr using:
host.sub.hash.domain.org.map.domain.org
sub.hash.domain.org.map.domain.org 
hash.domain.org.map.domain.org and so on. */
/* it returns 0 if no match, 1 if partial match, 2 if total match */
int getbaseaddr_mapdomain(struct in6_addr *baseaddr, char *name);

/* set and get the mapfile definition */
void getbaseaddr_setmapfile(char *path);
char *getbaseaddr_getmapfile(void);

/* set the mapdomain */
void getbaseaddr_setmapdomain(char *domain);
#endif
