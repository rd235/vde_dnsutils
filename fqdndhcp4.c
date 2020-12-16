/*   
 *   fqdndhcp.c: IPv4 dhcp server based on DNS queries
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
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
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <utils.h>
#include <name_utils.h>
#include <resolv.h>

#include <ctype.h>
#define STDMTU 1514
//#define PACKETDUMP

#define 	DHCP_CLIENTPORT 	68
#define 	DHCP_SERVERPORT 	67

#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

#define OPTION_PAD        0
#define OPTION_MASK       1
#define OPTION_ROUTER     3
#define OPTION_DNS        6
#define OPTION_HOSTNAME  12
#define OPTION_DOMNAME   15
#define OPTION_BROADCAST 28
#define OPTION_NTP       42
#define OPTION_REQIP     50
#define OPTION_LEASETIME 51
#define OPTION_TYPE      53
#define OPTION_SERVID    54
#define OPTION_PARLIST   55
#define OPTION_FQDN      81
#define OPTION_DOMAIN_LIST      119
#define OPTION_END      255

#define STDSERVID 0
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
static char *defgateway;
static char *defmask;

char mymac[6];

void generatemyaddr(void) {
	int i;
	unsigned int now=(unsigned int) time (NULL);
	srand (now);
	for (i=0; i<sizeof(mymac);i++)
		mymac[i]=rand();
	mymac[0] &= ~0x3;
}

int getxtra(char *fqdn, char *suffix, char *ipaddr) {
	char *fqdnx;
	char *firstdot = strchr(fqdn, '.');
	int hostnamelen;
	if (firstdot != NULL) {
		hostnamelen = firstdot - fqdn;
		asprintf(&fqdnx,"%*.*s%s%s",hostnamelen,hostnamelen,fqdn,suffix,firstdot);
		if (verbose)
			printf("search %s\n", fqdnx);
		if (fqdnx != NULL) {
			int retval = geta(fqdnx, ipaddr);
			free(fqdnx);
			return retval;
		}
	}
	return 0;
}

static char dhcp_cookie[] = {0x63,0x82,0x53,0x63};
#define BOOTP_VEND_LEN 64
__attribute__((__packed__)) struct bootp_head {
	unsigned char op;
	unsigned char htype;
	unsigned char hlen;
	unsigned char hops;
	char xid[4];
	char secs[2];
	char flags[2];
	char ciaddr[4];
	char yiaddr[4];
	char siaddr[4];
	char giaddr[4];
	char chaddr[16];
	char sname[64];
	char file[128];
	char vend[BOOTP_VEND_LEN];
};

__attribute__((__packed__)) struct dhcp_head {
	char dhcp_cookie[4];
};

__attribute__((__packed__)) struct dhcp_option {
	unsigned char opt_type;
	unsigned char opt_len;
	char opt_value[0];
};

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
	size_t len=opt->opt_len+sizeof(*opt);
	if (buf+len <= limit) {
		memcpy(buf,opt,len);
		return buf+len;
	} else 
		return buf;
}

char *add_end(char *buf, char *limit) {
	if (buf + 1 <= limit) {
		*buf = OPTION_END;
		return buf + 1;
	} else
		return buf;
}

char *add_opt1(char *buf, char *limit, char type, char value) {
	struct dhcp_option *opth=(struct dhcp_option *)buf;
	size_t len=sizeof(*opth) + 1;
	if (buf+len <= limit) {
		opth->opt_type = type;
		opth->opt_len = 1;
		opth->opt_value[0] = value;
		return buf+len;
	} else
		return buf;
}

char *add_opt(char *buf, char *limit, char type, char *value, size_t len) {
	struct dhcp_option *opth=(struct dhcp_option *)buf;
	if (buf+len <= limit) {
		opth->opt_type = type;
		opth->opt_len = len;
		memcpy(opth->opt_value, value, len);
		return buf+len+sizeof(*opth);
	} else
		return buf;
}

char *add_optlong(char *buf, char *limit, char type, unsigned long value) {
	char cvalue[4];
	en32(cvalue, value);
	return add_opt(buf, limit, type, cvalue, 4);
}

char *add_optshort(char *buf, char *limit, char type, unsigned short value) {
	char cvalue[2];
	en16(cvalue, value);
	return add_opt(buf, limit, type, cvalue, 2);
}

struct optlist {
	struct optlist *next;
	struct dhcp_option opt;
};
struct optlist *optlisth=NULL;

char *add_prl_options(char *buf, char *limit, struct dhcp_option *opt) {
	char *payload=(char *)(opt+1);
	size_t len=opt->opt_len;
	size_t i;
	struct optlist *scan;
	for (i=0; i<len; i++) {
		//printf("trying to add %ld\n",de16(payload+i));
		for (scan = optlisth; scan != NULL; scan = scan->next) {
			if (payload[i] == scan->opt.opt_type)
				break;
		}
		if (scan != NULL) 
			buf=copy_option(buf,limit,&scan->opt);
	}
	return buf;
}

void add_optlist(struct dhcp_option *opt) {
	size_t len=opt->opt_len;
	struct optlist *new=malloc(len+sizeof(struct optlist));
	if (new) {
		memcpy(&new->opt, opt, len+sizeof(struct dhcp_option));
		new->next=optlisth;
		optlisth=new;
	}
}

#define MAXOPT 255
void add_option_alist(unsigned int type, char *arg) {
	char buf[MAXOPT];
	struct dhcp_option *opt=(struct dhcp_option *)buf;
	char *payload=(char *)(opt + 1);
	char *pos=payload;
	char *str,*saveptr, *token;
	for (str=arg;pos<buf+MAXOPT;str=NULL,pos+=4) {
		token=strtok_r(str,",",&saveptr);
		if (token==NULL)
			break;
		if (geta((char *)token, pos) <= 0) {
			 printlog(LOG_ERR, "Addr error: %s", token);
			 exit(1);
		}
	}
	if (pos > payload) {
		opt->opt_type = type;
		opt->opt_len = pos-payload;
		add_optlist(opt);
	}
}

void add_option_fqdnlist(int type, char *arg) {
	char buf[MAXOPT];
	struct dhcp_option *opt=(struct dhcp_option *)buf;
	char *payload=(char *)(opt + 1);
	char *pos=payload;
	char *str,*saveptr, *token;
	unsigned int fieldlen;
	for (str=arg;pos<buf+MAXOPT;str=NULL,pos+=fieldlen) {
		token=strtok_r(str,",",&saveptr);
		if (token==NULL)
			break;
		fieldlen=name2dns(token,pos);
	}
	if (pos > payload) {
		opt->opt_type = type;
		opt->opt_len = pos-payload;
		add_optlist(opt);
	}
}

size_t dhcpparse(struct dhcp_head *dhcph, size_t len, struct dhcp_head *rdhcph, size_t rlen, char *yiaddr) {
	char *optptr = ((char *) dhcph) + sizeof(*dhcph);
	char *roptptr = ((char *) rdhcph) + sizeof(*dhcph);
	struct dhcp_option *dhcptype=NULL;
	struct dhcp_option *fqdnopt=NULL;
	struct dhcp_option *prlopt=NULL;
	char *buflimit = (char *)dhcph + len;
	char *rbuflimit = (char *)rdhcph + rlen;
	if (memcmp(dhcph->dhcp_cookie, dhcp_cookie, sizeof(dhcp_cookie)) != 0)
		return 0;
	memcpy(rdhcph->dhcp_cookie, dhcp_cookie, sizeof(dhcp_cookie));
	while (optptr < buflimit) {
		struct dhcp_option *opt = (struct dhcp_option *) optptr;
		int opttag = opt->opt_type;
#ifdef PACKETDUMP
		printf("option %u\n",opttag);
#endif
		if (opttag == OPTION_END)
			break;
		else if (opttag == OPTION_PAD) {
			optptr++;
			continue;
		} else {
			switch (opttag) {
				case OPTION_TYPE:
					dhcptype = opt;
					break;
				case OPTION_FQDN:
					fqdnopt = opt;
					break;
				case OPTION_PARLIST:
					prlopt = opt;
					break;
			}
			optptr += sizeof(*opt) + opt->opt_len;
		}
	}
	*rdhcph = *dhcph;
	if (dhcptype) {
		char dhcp_type = dhcptype->opt_value[0];
		if (verbose)
			printf("dhcp_type %d\n",dhcp_type);
		if (fqdnopt) {
			char fqdn[255];
			char xtraddr[4];
			if (fqdnopt->opt_value[0] & 0x4) 
				getname(NULL, &fqdnopt->opt_value[3], fqdn, ((char *)fqdnopt) + fqdnopt->opt_len);
			else {
				int fqdnlen = fqdnopt->opt_len - 3;
				memcpy(fqdn, &fqdnopt->opt_value[3], fqdnlen);
				fqdn[fqdnlen] = 0;
			}
			if (verbose)
				printf("FQDN = %s\n",fqdn);
			switch (dhcp_type) {
				case DHCPDISCOVER:
					if (geta(fqdn, yiaddr) > 0) {
						roptptr = add_opt1(roptptr, rbuflimit, OPTION_TYPE, DHCPOFFER);
						roptptr = add_optlong(roptptr, rbuflimit, OPTION_SERVID, STDSERVID);
						roptptr = add_optlong(roptptr, rbuflimit, OPTION_LEASETIME, STDVALID);
						if (geta(defmask, xtraddr) > 0 || getxtra(fqdn,"-mask",xtraddr) > 0)
								roptptr = add_opt(roptptr, rbuflimit, OPTION_MASK, xtraddr, 4);
						if (geta(defgateway, xtraddr) > 0 || getxtra(fqdn,"-gw",xtraddr) > 0)
								roptptr = add_opt(roptptr, rbuflimit, OPTION_ROUTER, xtraddr, 4);
						if (prlopt) 
							roptptr = add_prl_options(roptptr, rbuflimit, prlopt);
						roptptr = add_end(roptptr, rbuflimit);
						return roptptr-(char *)rdhcph;
					}
					break;
				case DHCPREQUEST:
					if (geta(fqdn, yiaddr) > 0) {
						roptptr = add_opt1(roptptr, rbuflimit, OPTION_TYPE, DHCPACK);
						roptptr = add_optlong(roptptr, rbuflimit, OPTION_SERVID, STDSERVID);
						roptptr = add_optlong(roptptr, rbuflimit, OPTION_LEASETIME, STDVALID);
						if (geta(defmask, xtraddr) > 0 || getxtra(fqdn,"-mask",xtraddr) > 0)
								roptptr = add_opt(roptptr, rbuflimit, OPTION_MASK, xtraddr, 4);
						if (geta(defgateway, xtraddr) > 0 || getxtra(fqdn,"-gw",xtraddr) > 0)
								roptptr = add_opt(roptptr, rbuflimit, OPTION_ROUTER, xtraddr, 4);
						if (prlopt) 
							roptptr = add_prl_options(roptptr, rbuflimit, prlopt);
						roptptr = add_end(roptptr, rbuflimit);
						return roptptr-(char *)rdhcph;
					}
					break;
			}
		}
	}
	return 0;
}

size_t bootpparse(struct bootp_head *bootph, size_t len, struct bootp_head *rbootph, size_t rlen) {
	if (verbose)
		printf("bootp op %d htype %d hlen %d \n", bootph->op, bootph->htype, bootph->hlen);
	if (bootph->op == 1 || bootph->htype == 1 || bootph->hlen == 6) {
		size_t rdhcp_size;
		size_t bootp_net_size = sizeof(*bootph) - BOOTP_VEND_LEN;
		struct dhcp_head *dhcph = (struct dhcp_head *) bootph->vend;
		struct dhcp_head *rdhcph = (struct dhcp_head *) rbootph->vend;
		memcpy(rbootph, bootph, bootp_net_size);
		rbootph->op = 2;
		memset(rbootph->vend, 0, BOOTP_VEND_LEN);
		rdhcp_size = dhcpparse(dhcph, len - bootp_net_size, rdhcph, rlen - bootp_net_size, rbootph->yiaddr);
		if (rdhcp_size > 0) {
			if (rdhcp_size < 64)  rdhcp_size = 64;
			return rdhcp_size + sizeof(*bootph) - BOOTP_VEND_LEN;
		}
	}
	return 0;
}

/* set up the headers fill in len, checksum and send packet */
size_t eth_pktout(char *bufin, char *bufout, ssize_t n) {
	struct ether_header *ethh = (struct ether_header *)bufout;
	struct iphdr *iph = (struct iphdr *)(ethh+1);
	struct udphdr *udph = (struct udphdr *)(iph+1);
	size_t headlen = (sizeof(*ethh) + sizeof(*iph) + sizeof(*udph));
	size_t len = n - sizeof(*ethh) - sizeof(*iph);
	unsigned int sum=0;
	memcpy(bufout,bufin,headlen);
	/* ETH */
	memcpy(ethh->ether_dhost,ethh->ether_shost,6);
	memcpy(ethh->ether_shost,mymac,6);
	/* IP */
	//iph->daddr = iph->saddr;
	iph->daddr = 0xffffffff;
	iph->saddr = 0;
	iph->tot_len = htons(n - sizeof(*ethh));
	iph->check = 0;
	sum = chksum(sum, iph, 20);
	iph->check = htons(~sum);
	/* UDP */
	udph->dest= udph->source;
	udph->source=htons(DHCP_SERVERPORT);
	udph->len=htons(len);
	udph->check=0;
#ifdef PACKETDUMP
	packetdump(stderr, bufout,n);
#endif
	return n;
}

size_t eth_pktin(char *buf, ssize_t n, char *replybuf, ssize_t replybuflen) {
	struct ether_header *ethh = (struct ether_header *)buf;
	struct iphdr *iph = (struct iphdr *)(ethh+1);
	struct udphdr *udph = (struct udphdr *)(iph+1);
	struct bootp_head *bootph = (struct bootp_head *)(udph+1);
	size_t headlen = (sizeof(*ethh) + sizeof(*iph) + sizeof(*udph));
	struct bootp_head *rbootph = (struct bootp_head *)(replybuf + headlen);
	size_t replylen;
	if (ntohs(ethh->ether_type) != 0x0800) return 0; // this is not IPv4
	if (iph->version != 4) return 0; //this is not IPv6
	if (iph->protocol != 17) return 0; //this is not UDP
	if (ntohs(udph->dest) != DHCP_SERVERPORT) return 0; /* wrong destination port */
	if (n >= headlen+(sizeof(*bootph) - BOOTP_VEND_LEN) && (replylen=bootpparse(bootph,n-headlen,rbootph,replybuflen - headlen)) > 0) {
		return eth_pktout(buf, replybuf, replylen+headlen);
	} else
		return 0;
}

//char dhcp_ethernet_addr[]={0x33,0x33,0x00,0x01,0x00,0x02};
char dhcp_ethernet_addr[]={0xff,0xff,0xff,0xff,0xff,0xff};
void main_vde_loop(VDECONN *conn) 
{
	ssize_t n;
	while (1) {
		char buf[STDMTU];
		char replybuf[STDMTU];
		n=vde_recv(conn,buf,STDMTU,0);
		if (n<=0) return;
		if (n >= 14 && (memcmp(buf,dhcp_ethernet_addr,sizeof(dhcp_ethernet_addr))==0 ||
					memcmp(buf,mymac,sizeof(mymac))==0)) {
#ifdef PACKETDUMP
			printf("INPACKET %zd\n",n);
			packetdump(stderr, buf,n);
#endif
			if ((n = eth_pktin(buf, n, replybuf, STDMTU)) > 0) 
				vde_send(conn, replybuf, n, 0);
		}
	}
}

static struct sock_filter filterprog[] = {
	// It is IPv4
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, offsetof(struct ethhdr, h_proto)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETH_P_IP, 0, 9),
	// to 255.255.255.255
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ETH_HLEN + offsetof(struct iphdr, daddr)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xffffffff, 0, 7),
	// it is UDP
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, ETH_HLEN + offsetof(struct iphdr, protocol)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_UDP, 0, 5),
	// it is not a fragment
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, ETH_HLEN + offsetof(struct iphdr, frag_off)),
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 0x1fff, 3, 0),
	// UDP port == 67
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, ETH_HLEN + sizeof(struct iphdr) +
			offsetof(struct udphdr, dest)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x43, 0, 1),
	// return the entire packet
	BPF_STMT(BPF_RET+BPF_K, 0x640),
	// filter this packet
	BPF_STMT(BPF_RET+BPF_K, 0),
};

static struct sock_fprog filter = {
	.filter = filterprog,
	.len = sizeof(filterprog) / sizeof(filterprog[0])
};

int open_iface(char *interface) {
	int fd;
	int ifindex = if_nametoindex(interface);
	struct sockaddr_ll bindaddr;
	if (ifindex == 0) {
		perror(interface);
		return -1;
	}
	generatemyaddr();
	if ((fd=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
		return -1;
	memset(&bindaddr, 0, sizeof(bindaddr));
	memcpy(bindaddr.sll_addr, &mymac, sizeof(mymac));
	bindaddr.sll_family = AF_PACKET; 
	bindaddr.sll_protocol = htons(ETH_P_IP);
	bindaddr.sll_ifindex = ifindex;
	bindaddr.sll_halen = sizeof(mymac);
	bindaddr.sll_pkttype = PACKET_BROADCAST;
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0)
		goto error;
	if ((bind(fd, (struct sockaddr *) &bindaddr, sizeof(bindaddr))) < 0) 
		goto error;
	return fd;
error:
	perror("open_iface");
	close(fd);
	return -1;
}

#define DHCP_PACKET_SIZE (STDMTU-sizeof(struct ip6_hdr)-sizeof(struct udphdr))
void main_iface_loop(int fd) {
	struct sockaddr_ll from;
	socklen_t fromlen;
	ssize_t n;
	while (1) {
		char buf[STDMTU];
		char replybuf[STDMTU];
		n=recvfrom(fd, buf, DHCP_PACKET_SIZE, 0, (struct sockaddr *) &from, &fromlen);
		printf("got msg\n");
#ifdef PACKETDUMP
		printf("INPACKET %zd\n",n);
		packetdump(stderr, buf,n);
#endif
		if ((n = eth_pktin(buf, n, replybuf, STDMTU)) > 0)
			send(fd, replybuf, n, 0);
	}
}

void usage(char *progname)
{
	fprintf(stderr,"Usage: %s OPTIONS\n"
			"\t--sock|--switch|-s vde_switch\n"
			"\t--iface|-i interface\n"
			"\t--resolver|-r dns (used by this dhcp server)\n"
			"\t--dns|-D (dhcp option sent to clients)\n"
			"\t--mask|-m mask"
			"\t--gw|-g gateway"
			"\t--dnssearch|-S\n"
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
	static char *short_options = "hdvs:i:D:S:r:m:g:";
	static struct option long_options[] = {
		{"help", 0, 0, 'h'},
		{"daemon", 0, 0, 'd'},
		{"pidfile", 1, 0, PIDFILEARG},
		{"verbose", 0, 0, 'v'},
		{"switch", 1, 0, 's'},
		{"sock", 1, 0, 's'},
		{"dns", 1, 0, 'D'},
		{"dnssearch", 1, 0, 'S'},
		{"iface", 1, 0, 'i'},
		{"resolver", 1 , 0, 'r'},
		{"mask", 1 , 0, 'm'},
		{"gw", 1 , 0, 'g'},
		{0,0,0,0}
	};
	int option_index;
	progname=argv[0];
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
			case 'r':
				nameservers=optarg;
				break;
			case PIDFILEARG:
				pidfile=optarg;
				break;
			case 'D':
				add_option_alist(OPTION_DNS, optarg);
				break;
			case 'N':
				add_option_alist(OPTION_NTP, optarg);
				break;
			case 'S':
				add_option_fqdnlist(OPTION_DOMAIN_LIST, optarg);
				break;
			case 'm':
				defmask = optarg;
				break;
			case 'g':
				defgateway = optarg;
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

	if (interface) {
		//printf("interface %s\n",interface);
		int fd=open_iface(interface);
		if (fd >= 0) {
			main_iface_loop(fd);
			close(fd);
		}
	} else {

		VDECONN *vdeconn=vde_open(switch_path, "DHCPv4", NULL);

		generatemyaddr();
		if (vdeconn) {
			main_vde_loop(vdeconn);
			vde_close(vdeconn);
		}
	}
	return 0;
}
