#ifndef RESOLV_H
#define RESOLV_H

#include <string.h>

int init_resolv(char *nameservers);
int getaaaa(char *fqdn, char *ipaddr);
int geta(char *fqdn, char *ipaddr);

#endif
