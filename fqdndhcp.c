/*   
 *   fqdndhcp.c: IPv6 dhcp server based on (aaaa) DNS queries
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
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <libvdeplug.h>
#include <poll.h>
#include <mhash.h>
#include <getopt.h>
#include <syslog.h>
#include <stdarg.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <utils.h>
#include <name_utils.h>
#include <resolv.h>

#include <ctype.h>
#define STDMTU 1514
#define PACKETDUMP

#define 	DHCP_CLIENTPORT 	546
#define 	DHCP_SERVERPORT 	547
#define 	DHCP_SOLICIT 	1
#define 	DHCP_ADVERTISE 	2
#define 	DHCP_REQUEST 	3
#define 	DHCP_CONFIRM 	4
#define 	DHCP_RENEW 	5
#define 	DHCP_REBIND 	6
#define 	DHCP_REPLY 	7
#define 	DHCP_RELEASE 	8
#define 	DHCP_DECLINE 	9
#define 	DHCP_RECONFIGURE 	10

#define 	OPTION_CLIENTID 	1
#define 	OPTION_SERVERID 	2
#define 	OPTION_IA_NA 	3
#define 	OPTION_IA_TA 	4
#define 	OPTION_IAADDR  5
#define 	OPTION_ORO 	6
#define 	OPTION_PREFERENCE 	7
#define 	OPTION_ELAPSED_TIME 	8
#define 	OPTION_RELAY_MSG 	9
#define 	OPTION_AUTH 	11
#define 	OPTION_UNICAST 	12
#define 	OPTION_STATUS_CODE 	13
#define 	OPTION_RAPID_COMMIT 	14
#define 	OPTION_USER_CLASS 	15
#define 	OPTION_VENDOR_CLASS 	16
#define 	OPTION_VENDOR_OPTS 	17
#define 	OPTION_INTERFACE_ID 	18
#define 	OPTION_RECONF_MSG 	19
#define 	OPTION_RECONF_ACCEPT 	20
#define		OPTION_DNS_SERVERS	23
#define 	OPTION_DOMAIN_LIST 	24
#define 	OPTION_IAPREFIX 	26
#define 	OPTION_SNTP_SERVERS 	31
#define 	OPTION_CLIENT_FQDN 	39

#define STDRENEW 0
#define STDREBIND 0
#define STDPREF ~0
#define STDVALID ~0

static int daemonize; // daemon mode
static int verbose;
static char *cwd;
static char *pidfile;
static char *switch_path;
static char *interface;

char mymac[6];
/* multicast IPv6 address for DHCP */
char dhcpip[16] = {0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x02};
/* my link local ipv6 address */
char myllip[16] = {0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xfe,0x00,0x00,0x00};
/* my DHCP unique id */
char myduid[14] = {0x00,0x01,0x00,0x01}; //ethernet DUID MAC+Time
/* test string for UDP packets */
char isudp[2] = {0x00,0x11};

__attribute__((__packed__)) struct dhcp_head {
	char dhcp_type[1];
	char dhcp_tid[3];
};

__attribute__((__packed__)) struct dhcp_option {
	char opt_type[2];
	char opt_len[2];
};

/* checksum computation helper function */
unsigned int chksum(unsigned int sum, void *vbuf, size_t len) {
	unsigned char *buf=vbuf;
	int i;
	for (i=0; i<len; i++) 
		sum += (i%2)? buf[i]: buf[i]<<8;
	while (sum>>16)
		sum = (sum>>16) + (sum&0xffff);
	return sum;
}

/* copy an option as is */
char *copy_option(char *buf, char *limit, struct dhcp_option *opt) {
	size_t len=de16(opt->opt_len)+sizeof(*opt);
	if (buf+len <= limit) {
		memcpy(buf,opt,len);
		return buf+len;
	} else 
		return buf;
}

/* add server id */
char *add_serverid(char *buf, char *limit) {
	struct dhcp_option *opth=(struct dhcp_option *)buf;
	size_t len=sizeof(*opth)+sizeof(myduid);
	if (buf+len <= limit) {
		en16(opth->opt_type, OPTION_SERVERID);
		en16(opth->opt_len, sizeof(myduid));
		memcpy(buf+sizeof(*opth),myduid,sizeof(myduid));
		return buf+len;
	} else 
		return buf;
}

char *add_ipaddr(char *buf, char *limit,  char *ipaddr, unsigned long pref, unsigned long valid) {
	struct dhcp_option *opth=(struct dhcp_option *)buf;
	size_t len=24;
	if (buf+(len+sizeof(*opth)) <= limit) {
		en16(opth->opt_type, OPTION_IAADDR);
		en16(opth->opt_len, len);
		memcpy(buf+sizeof(*opth),ipaddr,16);
		en32(buf+sizeof(*opth)+16,pref);
		en32(buf+sizeof(*opth)+20,valid);
		return buf+(sizeof(*opth)+len);
	} else
		return buf;
}

#if 0
/* add IAPREFIX */
char *add_iaprefix(char *buf, char *limit,  char *ipaddr, unsigned long pref, unsigned long valid) {
	struct dhcp_option *opth=(struct dhcp_option *)buf;
	size_t len=25;
	if (buf+(len+sizeof(*opth)) <= limit) {
		en16(opth->opt_type, OPTION_IAPREFIX);
		en16(opth->opt_len, len);
		en32(buf+sizeof(*opth),pref);
		en32(buf+sizeof(*opth)+4,valid);
		buf[sizeof(*opth)+8] = 64;
		memcpy(buf+sizeof(*opth)+9, ipaddr, 8);
		memset(buf+sizeof(*opth)+17, 0, 8);
		return buf+(sizeof(*opth)+len);
	} else
		return buf;
}
#endif

/* success or error */
char *add_status_code(char *buf, char *limit, unsigned int code, char *msg) {
	struct dhcp_option *opth=(struct dhcp_option *)buf;
	size_t len=2+strlen(msg);
	if (buf+(len+sizeof(*opth)) <= limit) {
		char *payload=buf+sizeof(*opth);
		en16(opth->opt_type, OPTION_STATUS_CODE);
		en16(opth->opt_len, len);
		en16(payload, code);
		memcpy(payload+2,msg,len-2);
		return buf+(sizeof(*opth)+len);
	} else
		return buf;
}

/* IANA stands for ID association for non-temporary address */
char *add_iana(char *buf, char *limit,  char *ipaddr, char *iaid) {
	struct dhcp_option *opth=(struct dhcp_option *)buf;
	size_t len=12;
	if (buf+(len+sizeof(*opth)) <= limit) {
		char *inbuf=buf+(sizeof(*opth)+len);
		en16(opth->opt_type, OPTION_IA_NA);
		en32(buf+sizeof(*opth)+4,STDRENEW);
		en32(buf+sizeof(*opth)+8,STDREBIND);
		if (iaid)
			memcpy(buf+sizeof(*opth),iaid,4);
		else {
			int i;
			for (i=0;i<4;i++)
				(buf+sizeof(*opth))[i]=ipaddr[8+i] ^ ipaddr[12+i];
		}
		if (ipaddr) 
			inbuf = add_ipaddr(inbuf, limit, ipaddr, STDPREF, STDVALID);
		len = inbuf - (buf+sizeof(*opth));
		en16(opth->opt_len, len);
		return buf+(sizeof(*opth)+len);
	} else
		return buf;
}

/* Check if the proposed IANA can be confirmed */
int check_iana(struct dhcp_option *opth, char *ipaddr) {
	char *buf=(char *)opth;
	size_t len=de16(opth->opt_len);
	char *inbuf=buf+(sizeof(*opth)+12);
	len -=12;
	while (len > 0) {
		struct dhcp_option *opt2=(struct dhcp_option *)inbuf;
		if (de16(opt2->opt_type)==OPTION_IAADDR) {
#if 0
#ifdef PACKETDUMP
			if (verbose) {
				fprintf(stderr, "--->\n");
				packetdump(stderr, inbuf+sizeof(*opt2),16);
				packetdump(stderr, ipaddr,16);
				fprintf(stderr, "<---\n");
			}
#endif
#endif
			return memcmp(inbuf+sizeof(*opt2),ipaddr,16);
		}
	}
	return 0;
}

int check_serverid(struct dhcp_option *opth) {
	size_t len=de16(opth->opt_len);
	return (len == 14 && memcmp(opth+1, myduid, 14) == 0);
}

struct optlist {
	struct optlist *next;
	struct dhcp_option opt;
};
struct optlist *optlisth=NULL;

/* add requested options, those available in the optlisth list */
char *add_oro_options(char *buf, char *limit, struct dhcp_option *opt) {
	char *payload=(char *)(opt+1);
	size_t len=de16(opt->opt_len);
	size_t i;
	struct optlist *scan;
	for (i=0; i<len; i+=2) {
		//printf("trying to add %ld\n",de16(payload+i));
		for (scan = optlisth; scan != NULL; scan = scan->next) {
			if (memcmp(payload+i, scan->opt.opt_type, 2) == 0)
				break;
		}
		if (scan != NULL) 
			buf=copy_option(buf,limit,&scan->opt);
	}
	return buf;
}

/* add a simple option to the optlisth list */
void add_optlist(struct dhcp_option *opt) {
	size_t len=de16(opt->opt_len);
	struct optlist *new=malloc(len+sizeof(struct optlist));
	if (new) {
		memcpy(&new->opt, opt, len+sizeof(struct dhcp_option));
		new->next=optlisth;
		optlisth=new;
	}
}

/* add an option whose arg is a list of ipv6 addresses to the
	 optlisth list */
void add_option_aaaalist(unsigned int type, char *arg) {
	char buf[STDMTU];
	struct dhcp_option *opt=(struct dhcp_option *)buf;
	char *payload=(char *)(opt + 1);
	char *pos=payload;
	char *str,*saveptr, *token;
	for (str=arg;pos<buf+STDMTU;str=NULL,pos+=16) {
		token=strtok_r(str,",",&saveptr);
		if (token==NULL)
			break;
		if (getaaaa(token, pos) <= 0) {
			 printlog(LOG_ERR, "Addr error: %s", token);
			 exit(1);
		}
	}
	if (pos > payload) {
		en16(opt->opt_type, type);
		en16(opt->opt_len, pos-payload);
		add_optlist(opt);
	}
}

/* add an option whose arg is a list of fully qualified 
	 domain names to the optlisth list */
void add_option_fqdnlist(int type, char *arg) {
	char buf[STDMTU];
	struct dhcp_option *opt=(struct dhcp_option *)buf;
	char *payload=(char *)(opt + 1);
	char *pos=payload;
	char *str,*saveptr, *token;
	unsigned int fieldlen;
	for (str=arg;pos<buf+STDMTU;str=NULL,pos+=fieldlen) {
		token=strtok_r(str,",",&saveptr);
		if (token==NULL)
			break;
		fieldlen=name2dns(token,pos);
	}
	if (pos > payload) {
		en16(opt->opt_type, type);
		en16(opt->opt_len, pos-payload);
		add_optlist(opt);
	}
}

/* DHCP protocol */
size_t dhcpparse(struct dhcp_head *dhcph, size_t len, struct dhcp_head *rdhcph, size_t rlen) {
	char *optptr = ((char *) dhcph) + sizeof(*dhcph);
	char *roptptr = ((char *) rdhcph) + sizeof(*dhcph);
	struct dhcp_option *clientid=NULL;
	struct dhcp_option *serverid=NULL;
	struct dhcp_option *iana=NULL;
	struct dhcp_option *fqdnopt=NULL;
	struct dhcp_option *oroopt=NULL;
	char *buflimit = (char *)dhcph + len;
	char *rbuflimit = (char *)rdhcph + rlen;
	if (verbose)
		fprintf(stderr, "DHCPTYPE %u\n", dhcph->dhcp_type[0]);
	while (optptr < buflimit) {
		struct dhcp_option *opt = (struct dhcp_option *) optptr;
		int opttag = (opt->opt_type[0]<<8) + opt->opt_type[1];
		if (verbose) 
			fprintf(stderr, "option %u\n",opttag);
		switch (opttag) {
			case OPTION_CLIENTID:
				clientid = opt;
				break;
			case OPTION_SERVERID:
				serverid = opt;
				break;
			case OPTION_IA_NA:
				iana = opt;
				break;
			case OPTION_CLIENT_FQDN: //FQDN
				fqdnopt = opt;
				break;
			case OPTION_ORO: 
				oroopt = opt;
				break;
		}
		optptr += sizeof(*opt) + (opt->opt_len[0] << 8) + opt->opt_len[1];
	}
	*rdhcph = *dhcph;
	if (fqdnopt) {
		char fqdn[MAXNAME];
		char ipv6addr[16];
		optptr = (char *) fqdnopt;
		getname((char *)dhcph, optptr+sizeof(*fqdnopt)+1, fqdn, optptr + sizeof(*fqdnopt) + (fqdnopt->opt_len[0] << 8) + fqdnopt->opt_len[1]);
		switch (dhcph->dhcp_type[0]) { //Solicit
			case DHCP_SOLICIT: 
				//printf("FQDN %s\n",fqdn);
				if (getaaaa(fqdn, ipv6addr) > 0) {
					rdhcph->dhcp_type[0]=DHCP_ADVERTISE;
					if (clientid) {
						roptptr=copy_option(roptptr,rbuflimit,clientid);
						roptptr=add_serverid(roptptr,rbuflimit);
					}
					roptptr=add_iana(roptptr,rbuflimit,ipv6addr,NULL);
					roptptr=copy_option(roptptr,rbuflimit,fqdnopt);
					return roptptr-(char *)rdhcph;
				}
				break;
			case DHCP_REQUEST: 
			case DHCP_CONFIRM: 
			case DHCP_RENEW: 
			case DHCP_REBIND: 
				//printf("req FQDN %s\n",fqdn);
				if (getaaaa(fqdn, ipv6addr) > 0 && check_iana(iana, ipv6addr)==0) {
					if (verbose)
						fprintf(stderr, "CONFIRM\n");
					rdhcph->dhcp_type[0]=DHCP_REPLY;
					if (clientid) {
						roptptr=copy_option(roptptr,rbuflimit,clientid);
						roptptr=add_serverid(roptptr,rbuflimit);
					}
					roptptr=add_iana(roptptr,rbuflimit,ipv6addr,(char *)(iana+1));
					roptptr=copy_option(roptptr,rbuflimit,fqdnopt);
					if (oroopt)
						roptptr=add_oro_options(roptptr,rbuflimit,oroopt);
					return roptptr-(char *)rdhcph;
				} else {
					if (verbose)
						fprintf(stderr, "NEW ADDR\n");
					rdhcph->dhcp_type[0]=DHCP_REPLY;
					if (clientid) {
						roptptr=copy_option(roptptr,rbuflimit,clientid);
						roptptr=add_serverid(roptptr,rbuflimit);
					}
					roptptr=add_status_code(roptptr,rbuflimit,4,"invalid addr");
					roptptr=copy_option(roptptr,rbuflimit,fqdnopt);
					return roptptr-(char *)rdhcph;
				}
				break;
		}
	} 
	switch (dhcph->dhcp_type[0]) {
		case DHCP_RELEASE:
		case DHCP_DECLINE:
			if (check_serverid(serverid)) {
				rdhcph->dhcp_type[0]=DHCP_REPLY;
				if (clientid) {
					roptptr=copy_option(roptptr,rbuflimit,clientid);
					roptptr=add_serverid(roptptr,rbuflimit);
				}
				roptptr=add_status_code(roptptr,rbuflimit,0,"success");
				return roptptr-(char *)rdhcph;
			}
	}
	return 0;
}

/* VDE case */

/* Generate a random MAC and compute the correspondent Link local address */
void generatemyaddr(void) {
	int i;
	unsigned int now=(unsigned int) time (NULL);
	srand (now);
	for (i=0; i<sizeof(mymac);i++)
		mymac[i]=rand();
	mymac[0] &= ~0x3;
	for (i=0; i<3; i++)
		myllip[8+i]=mymac[i];
	for (i=3; i<6; i++)
		myllip[10+i]=mymac[i];
	for (i=0; i<4; i++)
		myduid[i+4]= now>>((3-i)*8);
	for (i=0; i<6; i++)
		myduid[i+8]= mymac[i];
}

/* set up the headers: fill in len, checksum and send packet */
void vde_send_reply(VDECONN *conn, char *bufin, char *bufout, ssize_t n) {
	struct ether_header *ethh = (struct ether_header *)bufout;
	struct ip6_hdr *ipv6h = (struct ip6_hdr *)(ethh+1);
	struct udphdr *udph = (struct udphdr *)(ipv6h+1);
	size_t headlen = (sizeof(*ethh) + sizeof(*ipv6h) + sizeof(*udph));
	size_t len = n - sizeof(*ethh) - sizeof(*ipv6h);
	unsigned int sum=0;
	memcpy(bufout,bufin,headlen);
	/* ETH */
	memcpy(ethh->ether_dhost,ethh->ether_shost,6);
	memcpy(ethh->ether_shost,mymac,6);
	/* IP */
	memcpy(ipv6h->ip6_dst.s6_addr, ipv6h->ip6_src.s6_addr, 16);
	memcpy(ipv6h->ip6_src.s6_addr, myllip, 16);
	ipv6h->ip6_plen=htons(len);
	/* UDP */
	udph->dest= udph->source;
	udph->source=htons(DHCP_SERVERPORT);
	udph->len=htons(len);
	udph->check=0;
	sum = chksum(sum, ipv6h->ip6_src.s6_addr,16);
	sum = chksum(sum, ipv6h->ip6_dst.s6_addr,16);
	sum = chksum(sum, isudp, 2);
	sum = chksum(sum, &ipv6h->ip6_plen,2);
	sum = chksum(sum, (char *) udph, len);
	udph->check=htons(~sum);
	vde_send(conn,bufout,n,0);
}

void vdepktin(VDECONN *conn, char *buf, ssize_t n) {
	struct ether_header *ethh = (struct ether_header *)buf;
	struct ip6_hdr *ipv6h = (struct ip6_hdr *)(ethh+1);
	struct udphdr *udph = (struct udphdr *)(ipv6h+1);
	struct dhcp_head *dhcph = (struct dhcp_head *)(udph+1);
	size_t headlen = (sizeof(*ethh) + sizeof(*ipv6h) + sizeof(*udph));
	char replybuf[STDMTU];
	struct dhcp_head *rdhcph = (struct dhcp_head *)(replybuf + headlen);
	size_t replylen;
	if (ntohs(ethh->ether_type) != 0x86dd) return; // this is not IPv6
	if (ipv6h->ip6_vfc >> 4 != 6) return; //this is not IPv6
	if (memcmp(ipv6h->ip6_src.s6_addr, myllip, 2)!=0) return; //this is not Link Local
	if (ipv6h->ip6_nxt != 17) return; //this is not UDP
	if (ntohs(udph->dest) != DHCP_SERVERPORT) return; /* wrong destination port */
	if (n > headlen+sizeof(*dhcph) && (replylen=dhcpparse(dhcph,n-headlen,rdhcph,STDMTU-headlen)) > 0) {
#ifdef PACKETDUMP
		if (verbose)
			packetdump(stderr, replybuf,replylen);
#endif
		vde_send_reply(conn,buf,replybuf,replylen+headlen);
	}
}

char dhcp_ethernet_addr[]={0x33,0x33,0x00,0x01,0x00,0x02};
void main_vde_loop(VDECONN *conn) 
{
	ssize_t n;
	while (1) {
		char buf[2*STDMTU];
		n=vde_recv(conn,buf,STDMTU,0);
		if (n<=0) return;
		if (n >= 14 && (memcmp(buf,dhcp_ethernet_addr,sizeof(dhcp_ethernet_addr))==0 ||
					memcmp(buf,mymac,sizeof(mymac))==0)) {
#ifdef PACKETDUMP
			if (verbose) {
				fprintf(stderr, "INPACKET %zd\n",n);
				packetdump(stderr, buf,n);
			}
#endif
			vdepktin(conn, buf,n);
		}
	}
}

/* Inferface case */

int get_link_local_addr(char* if_name, struct sockaddr_in6 *ip)
{
	struct ifaddrs *ifaddr, *ifa;
	size_t if_name_length=strlen(if_name);
	unsigned int now=(unsigned int) time (NULL);

	if (getifaddrs(&ifaddr) == -1) 
		return -1;
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		struct sockaddr_in6 *current_addr;
		struct in6_addr *ipaddr;
		int i;
		/* check it is IPv6 */
		if (ifa->ifa_addr->sa_family != AF_INET6) continue;
		/* check: it is the right iface */
		if (strncmp(ifa->ifa_name, if_name, if_name_length)) continue;
		/* check: it is link local */
		current_addr = (struct sockaddr_in6 *) ifa->ifa_addr;
		if (memcmp(current_addr->sin6_addr.s6_addr, myllip, 8) != 0) continue;
		/* got it! */
		memcpy(ip, current_addr, sizeof(*current_addr));
		for (i=0; i<4; i++)
			myduid[i+4]= now>>((3-i)*8);
		ipaddr=&ip->sin6_addr;
		myduid[8]= ipaddr->s6_addr[8];
		myduid[9]= ipaddr->s6_addr[9];
		myduid[10]= ipaddr->s6_addr[10];
		myduid[11]= ipaddr->s6_addr[13];
		myduid[12]= ipaddr->s6_addr[14];
		myduid[13]= ipaddr->s6_addr[15];
#ifdef PACKETDUMP
		//packetdump(stderr, myduid,14);
		//packetdump(stderr, ipaddr,16);
#endif
		freeifaddrs(ifaddr);
		return 0;
	}
	errno = ENODEV;
	freeifaddrs(ifaddr);
	return -1;
}

int open_iface(char *interface) {
	struct sockaddr_in6 bindaddr;
	int fd = -1;
	struct ipv6_mreq mc_req;
	int ttl=1;
	int one=1;
	memset(&bindaddr, 0, sizeof(bindaddr));
	bindaddr.sin6_family      = AF_INET6;
	if (get_link_local_addr(interface, &bindaddr) < 0)
		goto error;
	//packetdump(stderr, bindaddr.sin6_addr.s6_addr,16);
	if ((fd=socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		goto error;
	if ((setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
					&ttl, sizeof(ttl))) < 0)
		goto error;
	if ((setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
					&one, sizeof(one))) < 0)
		goto error;
	if (bindtodevice(fd, interface) < 0)
		goto error;
	memcpy(&bindaddr.sin6_addr, &in6addr_any, sizeof(in6addr_any));
	bindaddr.sin6_port        = htons(DHCP_SERVERPORT);
	if ((bind(fd, (struct sockaddr *) &bindaddr, sizeof(bindaddr))) < 0) 
		goto error;
	memcpy(&mc_req.ipv6mr_multiaddr, dhcpip, 16);
	mc_req.ipv6mr_interface = if_nametoindex(interface);
	//printf("interface # %d\n",if_nametoindex(interface));
	if ((setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
					&mc_req, sizeof(mc_req))) < 0)
		goto error;
	return fd;
error:
	printlog(LOG_ERR, "Error opening interface %s: %s", interface, strerror(errno));
	if (fd >= 0)
		close(fd);
	return -1;
}

#define DHCP_PACKET_SIZE (STDMTU-sizeof(struct ip6_hdr)-sizeof(struct udphdr))
void main_iface_loop(int fd) {
	struct sockaddr_in6 from;
	socklen_t fromlen;
	ssize_t n;
	ssize_t replylen;

	while (1) {
		char buf[DHCP_PACKET_SIZE];
		struct dhcp_head *dhcph = (struct dhcp_head *)buf;
		char replybuf[DHCP_PACKET_SIZE];
		struct dhcp_head *rdhcph = (struct dhcp_head *)replybuf;
		n=recvfrom(fd, buf, DHCP_PACKET_SIZE, 0, (struct sockaddr *) &from, &fromlen);
#ifdef PACKETDUMP
		if (verbose) {
			fprintf(stderr, "INPACKET %zd\n",n);
			packetdump(stderr, buf,n);
		}
#endif
		if ((replylen=dhcpparse(dhcph,n,rdhcph,DHCP_PACKET_SIZE)) > 0) {
#ifdef PACKETDUMP
			if (verbose) {
				fprintf(stderr, "OUTPACKET %zd\n",replylen);
				packetdump(stderr, replybuf,replylen);
			}
#endif
			sendto(fd, replybuf, replylen, 0,  (struct sockaddr *) &from, fromlen);
		}
	}
}


/* Main and command line args management */
void usage(char *progname)
{
	fprintf(stderr,"Usage: %s OPTIONS\n"
			"\t--sock|--switch|-s vde_switch\n"
			"\t--iface|-i interface\n"
			"\t--resolver|-r dns (used by this dhcp server)\n"
			"\t--dns|-D (dhcp option sent to clients)\n"
			"\t--dnssearch|-S\n"
			"\t--ntp|-N\n"
			"\t--help|-h\n"
			"\t--daemon|-d\n"
			"\t--pidfile pidfile\n"
			"\t--verbose|-v\n",
			progname);
	exit(1);
}

int main(int argc, char *argv[])
{
	char *progname = basename(argv[0]);
	char *nameservers = NULL;

#define PIDFILEARG 131
	static char *short_options = "hdvns:i:D:N:S:r:";
	static struct option long_options[] = {
		{"help", 0, 0, 'h'},
		{"daemon", 0, 0, 'd'},
		{"pidfile", 1, 0, PIDFILEARG},
		{"verbose", 0, 0, 'v'},
		{"switch", 1, 0, 's'},
		{"sock", 1, 0, 's'},
		{"dns", 1, 0, 'D'},
		{"dnssearch", 1, 0, 'S'},
		{"ntp", 1, 0, 'N'},
		{"iface", 1, 0, 'i'},
		{"resolver", 1 , 0, 'r'},
		{0,0,0,0}
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
			case PIDFILEARG:
				pidfile=optarg;
				break;
			case 'D':
				add_option_aaaalist(OPTION_DNS_SERVERS, optarg);
				break;
			case 'N':
				add_option_aaaalist(OPTION_SNTP_SERVERS, optarg);
				break;
			case 'S':
				add_option_fqdnlist(OPTION_DOMAIN_LIST, optarg);
				break;
			case 'r':
				nameservers=optarg;
				break;
			default:
				usage(progname);
				break;
		}
	}

	if (optind < argc)
		usage(progname);

	startlog(progname, daemonize);
	/* saves current path in cwd, because otherwise with daemonize() we
	 * forget it */
	if((cwd = getcwd(NULL, PATH_MAX)) == NULL) {
		printlog(LOG_ERR, "getcwd: %s", strerror(errno));
		exit(1);
	}
	if (daemonize && daemon(0, 0)) {
		printlog(LOG_ERR,"daemon: %s", strerror(errno));
		exit(1);
	}

	/* once here, we're sure we're the true process which will continue as a
	 * server: save PID file if needed */
	if(pidfile) save_pidfile(pidfile, cwd);

	if (init_resolv(nameservers) != 0) {
		printlog(LOG_ERR, "resolv library init error");
		exit(1);
	}

	if (interface) {
		int fd=open_iface(interface);
		if (fd >= 0) {
			main_iface_loop(fd);
			close(fd);
		} else 
			exit(1);
	} else {

		VDECONN *vdeconn=vde_open(switch_path, "DHCPv6", NULL);

		generatemyaddr();
		if (vdeconn) {
			main_vde_loop(vdeconn);
			vde_close(vdeconn);
		}
	}
	return 0;
}
