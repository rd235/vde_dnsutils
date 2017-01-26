/*   
 *   hashdns.c: HASH based DNS
 *   
 *   Copyright 2016, 2017 Renzo Davoli - Virtual Square Team 
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
#include <stddef.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <mhash.h>
#include <getopt.h>
#include <syslog.h>
#include <stdarg.h>
#include <ctype.h>
#include <vdestack.h>
#include "revdb.h"
#include "dnsmsgs.h"
#include "getbaseaddr.h"
#include "utils.h"
#include "name_utils.h"
#include "resolv.h"
#define BUFSIZE 1024
//#define PACKETDUMP

#ifndef LWIP_STACK_FLAG_NO_ECHO
#define LWIP_STACK_FLAG_NO_ECHO 0
#endif

int verbose;
static int daemonize; // daemon mode
static char *cwd;
static char *pidfile;
static char *switch_path;
static char *interface;
static enum {NEVER, ALWAYS, SAME, NET} reverse_policy = ALWAYS;
static char *reverse_policy_str[] = {"never", "always", "same", "net"};

/* compute the hash based address */
static int computeaddr(struct in6_addr *addr,char *uname) {
	char *name=(char *)uname;
	MHASH td;
	char out[mhash_get_block_size(MHASH_MD5)];
	int getval;
	int i;
	if (verbose)
		printf("Resolving: %s\n",name);
	/* search the base address */
	if ((getval=getbaseaddr_mapfile(addr,name)) == 0
	 && (getval=getbaseaddr_mapdomain(addr,name)) == 0) {
		if (verbose) printf("  FAILED\n");
		return 0;
	}
	if (verbose)
		packetdump(stderr, addr, 16);
	if (name[strlen(name)-1] == '.') name[strlen(name)-1]=0;
	if (getval == 2)
		memset(out, 0,sizeof(out));
	else {
		td=mhash_init(MHASH_MD5);
		mhash(td, name, strlen(name));
		mhash_deinit(td, out);
	}
#if 0
	printin6addr(stderr, addr);
#endif
	for (i=8; i<16; i++) 
		addr->s6_addr[i] ^= out[i-8] ^ out[i];
#if 0
	printin6addr(stderr, addr);
#endif
	return 1;
}

#define REVTAIL "ip6.arpa."

static int getrevaddr(char *name, struct in6_addr *addr) {
	int i,j;
	//printf("%d %s\n",strlen(name),name+64);
	if (strlen(name) != 73 || strcmp(name+64,REVTAIL) != 0)
		return 0;
	for (i=0,j=60; i<16; i++,j-=4) {
		char byte[3]={0, 0, 0};
		if (name[j+1] != '.' || name[j+3] != '.' || 
				!isxdigit(name[j]) || !isxdigit(name[j+2]))
			return 0;
		byte[0]=name[j+2],byte[1]=name[j];
		addr->s6_addr[i] = strtol(byte,NULL, 16);
	}
	return 1;
}

int check_reverse_policy(struct in6_addr *addr, struct in6_addr *fromaddr) {
	//printin6addr(stderr, addr);
	//printin6addr(stderr, fromaddr);
	switch (reverse_policy) {
		case ALWAYS:
			return 1;
		case SAME:
			return memcmp(addr, fromaddr, 16) == 0;
		case NET:
			return memcmp(addr, fromaddr, 8) == 0;
		default:
			return 0;
	}
}

ssize_t dnsparse(char *buf, struct sockaddr_in6 *from, ssize_t n) {
	struct dnshead *dnspkt = (struct dnshead *) buf;
	char fqdn[MAXNAME];
	struct querytail *querytail;
	unsigned int qtype;
	if (n < sizeof(struct dnshead))
		return 0;
#ifdef PACKETDUMP
	printf("INPACKET %ld\n",n);
	packetdump(stderr, buf,n);
#endif
	if (!isquery01(dnspkt->flags)) goto dnsparse_err;
	if (d16(dnspkt->nquery) != 1) goto dnsparse_err;
	//printf("it is a query\n");
	querytail = (struct querytail *) skipname(buf+sizeof(struct dnshead));
	qtype=d16(querytail->type);
	getname(buf,buf+sizeof(struct dnshead),fqdn, buf+n);
	//printf("NAME %s CLASS %x TYPE %x\n",fqdn, d16(querytail->class), qtype);
	if (d16(querytail->class) != INCLASS)
		goto dnsparse_err;
	if (qtype == AAAATAG || qtype == ANYTAG) {
		struct in6_addr addr;
		struct reply *reply=(struct reply *)(querytail + 1);
		//printf("it is aaaa or any\n");
		if (computeaddr(&addr,fqdn)) {
			if (check_reverse_policy(&addr, &from->sin6_addr))
				ra_add((char *)fqdn,&addr);
			dnspkt->flags = e16(AUTHREPLY_FLAGS);
			dnspkt->nquery = dnspkt->nanswer = e16(1);
			dnspkt->nauth = dnspkt->nadd = e16(0);
			reply->shortname = e16(COPYNAME_TAG);
			reply->type = e16(AAAATAG);
			reply->class = e16(INCLASS);
			reply->ttl = e32(1);
			reply->len = e16(16);
			memcpy(reply->payload,addr.s6_addr, 16);
			n = ((char *)(reply + 1) + 16) - buf;
#ifdef PACKETDUMP
			printf("REPLY\n");
			packetdump(stderr, buf,n);
#endif
			return n;
		} 
	} else if (qtype == PTRTAG) {
		struct in6_addr addr;
		char *name;
		struct reply *reply=(struct reply *)(querytail + 1);
		//printf("it is ptr (reverse)\n");
		if (getrevaddr((char *)fqdn, &addr) && (name=ra_search(&addr)) != NULL) {
			unsigned int replynamelen=name2dns(name,reply->payload);
			//printf("NAME IS %s\n",name);
			dnspkt->flags = e16(AUTHREPLY_FLAGS);
			dnspkt->nquery = dnspkt->nanswer = e16(1);
			dnspkt->nauth = dnspkt->nadd = e16(0);
			reply->shortname = e16(COPYNAME_TAG);
			reply->type = e16(PTRTAG);
			reply->class = e16(INCLASS);
			reply->ttl = e32(ra_gettl());
			reply->len = e16(replynamelen);
			n = ((char *)(reply + 1) + replynamelen) - buf;
#ifdef PACKETDUMP
			printf("REPLY\n");
			packetdump(stderr, buf,n);
#endif
			return n;
		} 
	} 
dnsparse_err:
	dnspkt->flags = e16(AUTHFAIL_FLAGS);
	return n;
}

void main_parse_loop(int sock) 
{
	ssize_t n;
	while (1) {
		char buf[2*BUFSIZE];
		struct sockaddr_in6 from;

		socklen_t fromlen=sizeof(from);
		n=recvfrom(sock,buf,BUFSIZE, 0,(struct sockaddr *)&from,&fromlen);
		if (n<=0) return;
		if ((n = dnsparse(buf,&from,n)) > 0) {
			sendto(sock,buf,n, 0,(struct sockaddr *)&from,fromlen);
			ra_clean();
		}
	}
}

int set_reverse_policy(char *policy_str) {
	int i;
	for (i = 0; i < sizeof(reverse_policy_str)/sizeof(reverse_policy_str[0]); i++) {
		if (strcmp(policy_str, reverse_policy_str[i]) == 0) {
			reverse_policy = i;
			return 0;
		}
	}
	fprintf(stderr, "unknown reverse policy: %s\n", policy_str);
	return -1;
}

void usage(char *progname)
{
	fprintf(stderr,"Usage: %s OPTIONS DNSvirtserver[/mask][,defaultroute] ... \n"
			"\t--help|-h\n"
			"\t--sock|--switch|-s vde_switch\n"
			"\t--iface|-i interface\n"
			"\t--mapdomain|-D map_domain\n"
			"\t--mapfile|-f map_file\n"
			"\t--daemon|-d\n"
			"\t--pidfile pidfile\n"
			"\t--verbose|-v\n",
			progname);
	exit(1);
}

/* ./hashdns 2001:760:2e00:ff00::42 192.168.254.1 otipcs.v2.cs.unibo.it
	 DNS v server [/mask]   Real DNS  domain [domain] [domain]*/
int main(int argc, char *argv[])
{
	struct vdestack *stack;
	struct sockaddr_in6 bindsockaddr;
	int dnssock;
	char *progname = basename(argv[0]);
	char *nameservers = NULL;
#define PIDFILEARG 131
	static char *short_options = "hD:f:dvns:r:R:i:";
	static struct option long_options[] = {
		{"help", 0 , 0, 'h'},
		{"mapdomain", 1 , 0, 'D'},
		{"mapfile", 1 , 0, 'f'},
		{"daemon", 0 , 0, 'd'},
		{"pidfile", 1, 0, PIDFILEARG},
		{"verbose", 0 , 0, 'v'},
		{"switch", 1 , 0, 's'},
		{"sock", 1 , 0, 's'},
		{"iface", 1 , 0, 'i'},
		{"resolver", 1 , 0, 'r'},
		{"reverse", 1 , 0, 'R'},
		{0, 0, 0, 0}
	};
	int option_index;
	while(1) {
		int c;
		c = getopt_long (argc, argv, short_options,
				long_options, &option_index);
		if (c<0)
			break;
		switch (c) {
			case 'h':
				usage(progname);
				break;
			case 'D':
				getbaseaddr_setmapdomain(optarg);
				break;
			case 'f':
				getbaseaddr_setmapfile(optarg);
				break;
			case 'd':
				daemonize=1;
				break;
			case 'v':
				verbose=1;
				break;
			case 's':
				switch_path=optarg;
				break;
			case 'i':
				interface=optarg;
				break;
			case 'r':
				nameservers=optarg;
				break;
			case 'R':
				if (set_reverse_policy(optarg))
					usage(progname);
				break;
			case PIDFILEARG:
				pidfile=optarg;
				break;
			default:
				usage(progname);
				break;
		}
	}

	startlog(progname, daemonize);
	/* saves current path in cwd, because otherwise with daemonize() we
	 * forget it */
	if((cwd = getcwd(NULL, PATH_MAX)) == NULL) {
		printlog(LOG_ERR, "getcwd: %s", strerror(errno));
		exit(1);
	}
	if (daemonize && daemon(0, 0)) {
		printlog(LOG_ERR,"daemon: %s",strerror(errno));
		exit(1);
	}

	/* once here, we're sure we're the true process which will continue as a
	 * server: save PID file if needed */
	if(pidfile) save_pidfile(pidfile, cwd);

	if (init_resolv(nameservers) != 0) {
		printlog(LOG_ERR, "resolv library init error");
		exit(1);
	}

	if (load_mapfile() < 0) {
		printlog(LOG_ERR,"error loading mapfile %s",getbaseaddr_getmapfile());
		exit(1);
	}

	if (switch_path != NULL) {
		stack=vde_addstack(switch_path, NULL);

		if (stack == NULL) {
			printlog(LOG_ERR,"error opening VDE stack %s",switch_path);
			exit(1);
		}

		vde_stackcmd(stack, "/sbin/sysctl -q net.ipv6.conf.vde0.autoconf=0");
		vde_stackcmd(stack, "/bin/busybox ip link set up vde0");
		while (optind < argc) {
			char *gateway;
			char *smask;
			int maskbits;
			char *cmd;
			if ((gateway=strchr(argv[optind],',')) != NULL) 
				*gateway++=0;

			if ((smask=strchr(argv[optind],'/'))==NULL) 
				maskbits=64;
			else {
				maskbits=atoi(smask+1);
				*smask=0;
			}
			cmd = NULL;
			asprintf(&cmd, "/bin/busybox ip addr add %s/%d dev vde0", argv[optind], maskbits);
			if (verbose)
				printf("CMD %s\n",cmd);
			vde_stackcmd(stack, cmd);
			free(cmd);
			if (gateway) {
				cmd = NULL;
				asprintf(&cmd, "/bin/busybox ip route add default via %s", gateway);
				if (verbose)
					printf("CMD %s\n",cmd);
				vde_stackcmd(stack, cmd);
				free(cmd);
			}
			optind++;
		}
		if (verbose)
			vde_stackcmd(stack, "/bin/busybox ip addr");

		dnssock=vde_msocket(stack,AF_INET6,SOCK_DGRAM, 0);
	} else
		dnssock=socket(AF_INET6,SOCK_DGRAM, 0);

	if (interface && bindtodevice(dnssock, interface) < 0) {
		printlog(LOG_ERR, "bindtodevice %s", strerror(errno));
		exit(1);
	}
	memset(&bindsockaddr, 0, sizeof(bindsockaddr));
	bindsockaddr.sin6_family = AF_INET6;
	bindsockaddr.sin6_addr = in6addr_any;
	bindsockaddr.sin6_port = htons(53);
	if (bind(dnssock, (struct sockaddr *)&bindsockaddr,
				sizeof(struct sockaddr_in6)) < 0) {
		printlog(LOG_ERR, "bind %s", strerror(errno));
		exit(1);
	}
	main_parse_loop(dnssock);
	close(dnssock);
	if (switch_path != NULL) 
		vde_delstack(stack);
	return 0;
}
