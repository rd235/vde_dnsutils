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
#ifndef REVDB_H
#define REVDB_H
#define _GNU_SOURCE
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

void ra_add(char *name, struct in6_addr *addr);
char *ra_search(struct in6_addr *addr);
void ra_clean(void);
void ra_set_timeout(unsigned int timeout);
unsigned int ra_get_timeout(void);
#endif
