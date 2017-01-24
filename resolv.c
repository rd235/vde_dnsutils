/*   
 *   resolv.c: resolve fqdn to IPv4 or IPv6 address.
 *   the current implementation uses libadns to override /etc/resolv.donf configurations.
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
#include <string.h>

#define USE_ADNS
#ifdef USE_ADNS
#include <adns.h>
#include <stdlib.h>
#include <arpa/inet.h>

//#define ADNS_FLAGS adns_if_debug
#define ADNS_FLAGS adns_if_none
static adns_state adns;

int init_resolv(char *nameservers) {
	if (nameservers) {
		size_t nslen = strlen(nameservers)+1;
		char nslist[nslen];
		char *ns, *scan, *stmp;
		int rv;
		char *resolvconf = NULL;
		size_t resolvconflen = 0;
		FILE *rc_file = open_memstream(&resolvconf, &resolvconflen);
		strncpy(nslist, nameservers, nslen);
		for (ns = nslist; (scan = strtok_r(ns, ",", &stmp)) != NULL; ns = NULL)
			fprintf(rc_file, "nameserver %s\n", scan);
		fclose(rc_file);
		rv = adns_init_strcfg(&adns, ADNS_FLAGS, stderr, resolvconf);
		free(resolvconf);
		return rv;
	} else {
		return adns_init(&adns, ADNS_FLAGS, stderr);
	}
}

int getaaaa(char *fqdn, char *ipaddr) {
	int rv;
	adns_answer *answer = NULL;
	if (fqdn == NULL)
		return -1;

	if (inet_pton(AF_INET6, fqdn, ipaddr) > 0)
		return 1;

	rv = adns_synchronous(adns, fqdn, adns_r_aaaa, 0, &answer);
	if (rv == 0) {
		adns_status status = answer->status;
		if (status == adns_s_ok && answer->nrrs > 0) {
			memcpy(ipaddr,&answer->rrs.in6addr[0],sizeof(struct in6_addr));
			free(answer);
			return 1;
		}
		free(answer);
		if (status < adns_s_nxdomain)
			return -1;
		else
			return 0;
	}
	return -1;
}

int geta(char *fqdn, char *ipaddr) {
	int rv;
	adns_answer *answer = NULL;

	if (fqdn == NULL)
		return -1;

	if (inet_pton(AF_INET, fqdn, ipaddr) > 0)
		return 1;

	rv = adns_synchronous(adns, fqdn, adns_r_a, 0, &answer);
	if (rv == 0) {
		adns_status status = answer->status;
		if (status == adns_s_ok && answer->nrrs > 0) {
			memcpy(ipaddr,&answer->rrs.inaddr[0],sizeof(struct in_addr));
			free(answer);
			return 1;
		}
		free(answer);
		if (status < adns_s_nxdomain)
			return -1;
		else
			return 0;
	} 
	return -1;
}

#else
#include <sys/socket.h>
#include <netdb.h>

int init_resolv(char *nameservers) {
	if (nameservers != NULL)
		return -1;
	return 0;
}

/* there is no way from gai output to detect if the server is unreachable or
	 the name does not exist in the database */
int getaaaa(char *fqdn, char *ipaddr) {
	struct addrinfo hints;
	struct addrinfo *addr;
	int rv;

	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;
	if ((rv = getaddrinfo((char *)fqdn,0,&hints,&addr)) == 0) {
		struct sockaddr_in6 *sockaddr=(struct sockaddr_in6 *)addr->ai_addr;
		memcpy(ipaddr,&sockaddr->sin6_addr,16);
		freeaddrinfo(addr);
		return 1;
	} else if (rv == EAI_NONAME)
		return 0;
	else
		return -1;
}

int geta(char *fqdn, char *ipaddr) {
	struct addrinfo hints;
	struct addrinfo *addr;
	int rv;

	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	if ((rv = getaddrinfo((char *)fqdn,0,&hints,&addr)) == 0) {
		struct sockaddr_in *sockaddr=(struct sockaddr_in *)addr->ai_addr;
		memcpy(ipaddr,&sockaddr->sin_addr,4);
		freeaddrinfo(addr);
		return 1;
	} else if (rv == EAI_NONAME)
		return 0;
	else
		return -1;
}
#endif
