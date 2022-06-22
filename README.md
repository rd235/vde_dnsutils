# vde\_dnsutils
DNS utilities for vde projects (hashdns/fqdndhcp)

* vde\_dnsutils is deprecated. The new more general projects
[iothnamed](https://github.com/virtualsquare/iothnamed) and 
[namedhcp](https://github.com/virtualsquare/namedhcp) can provide
the functionnalities formerly provided by vde\_dnsutil.
This project is no longer actively maintained.

## Install vde\_dnsutils

### Pre-requisites:
vde\_dnsutils depends on the following libraries:
* libmhash
* libadns
* libvdeplug (vdeplug4)
* libvdestack

vde\_dnsutils uses the auto-tools, so the standard installation procedure is the following:
```
$ autoreconf -if
$ ./configure
$ make
$ sudo make install
```

## HASHDNS

General remark: hashdns, fqdndhcp and fqdndhcp4 run as foreground processes in the examples
below. This is to show how these tools work. All the programs included in this 
package provide options to run them as daemons.
* -d (or --daemon) run the program as a daemon, use syslog for logging
* -pidfile *pathname* store the id of the deamon process in a file at the specified pathname.

Hashdns is an IPv6 DNS server implementation providing forward and reverse
name resolution using hash based IP addresses.  This server should be
delegated for one or more domains. When it receives a query, it searches a
base address for the domain (using either a configuration file or one further
 DNS query) The resulting IPv6 address has the same higher 64bits as the base
address and the lower 64 bits computed as the result  of  a hash function
using as its parameters the fully qualified domain name and the lower 64 bits
of the base address.

### hashdns configuration

#### 1. delegate hashdns for a subdomain
e.g. add in the *bind* zone file of "mydomain.org":

```
hash-dns                300     A       10.20.30.1
hash-dns                300     AAAA    2001:1000:2000:3000::1
hash                    IN      NS      hash-dns
hash.mydomain.org       IN      AAAA    2001:1000:2000:3000::
```

where:
* 10.20.30.1 is the IPv4 address of the host running hashdns
* 2001:1000:2000:3000::1  is the IPv6 address of the host running hashdns
* hash is the name of the subdomain using hash based addresses, the NS line delegates the domain hash.mydomain.org to hash-dns.mydomin.org (so all the names like something.hash.mydomain.org or some.thing.hash.mydomain.org will be resolved by the hadns running at hash-dns.mydomain.org).
* the last line adds a AAAA record for hash.mydomain.org.mydomain.org for the base address of hash.mydomain.org (note that there is not a period after hash.mydomain.org).

details:
* in this case hash-dns and the base address for hash.mydomain.org appears to be on the same IPv6 subnet. It is not a requirement: the hashdns server and the addresses managed by that server can be on different networks
* in this case the base address is just a 64 bit prefix. It is possible to use a complete address (i.e. the lower 64 bits are not null).
The upper 64 bits will be copied in the hash generated addresses while the lower 64 bits will be used in the computation of the hash
based host address.

Update the serial number in the zone's SOA and reload the DNS tables.

A hashdns server can be delegated for several domains. This configuration
examples refers to *bind9*. Any other DNS server implementation can be used
instead on *bind*, just the syntax of the configuration file to define
addresses and delegate subdomains is different. 

Suggested step: test if the DNS configuration is correct:
```
$ host hash-dns.mydomain.org
hash-dns.mydomain.org has address 10.20.30.1
hash-dns.mydomain.org has IPv6 address 2001:1000:2000:3000::1
$ host hash.mydomain.org.mydomain.org
hash.mydomain.org.mydomain.org has IPv6 address 2001:1000:2000:3000::
```

#### 2A. run hashdns (on a real host)

Now it is time to start hash-dns on hash-dns.mydomain.org.

Check you are on the right host ;-)
```
hash-dns# ip addr
...
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
   link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
   inet 10.20.30.1/24 scope global eth0
      valid_lft forever preferred_lft forever
   inet6 2001:1000:2000:3000::1/64 scope global 
      valid_lft forever preferred_lft forever
   inet6 fe80::aabb:ccff:fedd:eeff/64 scope link 
      valid_lft forever preferred_lft forever
```
... and start the DNS server
```
hash-dns# hashdns -D mydomain.org -i eth0
```

-D means that the "tail" of the fully qualified name used to retrieve the base address is "mydomain.org",
	so the base address for hash.mydomain.org can be found as "hash.mydomain.org.mydomain.org". Please note
	that one hashdns server can support multiple domains. e.g. if it is delegated also for fuzzy.mydomain.org, the
	base address for this latter domain will be found as "fuzzy.mydomain.org.mydomain.org.

hashdns can get the base addresses also from a configuration file. Readers interested to this feature may refer to
the man page of hashdns (see option --mapfile or -f).

#### 2B. run hashdns (on a virtual VDE network)

Pre-condition: there is a VDE network, IPV4 10.20.30.0/24 and IPV6 2001:1000:2000:3000::/64 addresses are routed on that VDE network.
Let us suppose that it is a vxvde network: *vxvde://*. It is possible to use other models of VDE networks such as
legacy vde-2 switch based (e.g. *vde://*), vxvdex (*vxvdex://*), tap, p2p, udp etc. 
```
host$ hashdns -s vxvde:// -D mydomain.org 10.20.30.1/24,10.20.30.254 2001:1000:2000:3000::1,2001:1000:2000:3000::fe
```
(10.20.30.254 and 2001:1000:2000:3000::fe are the addresses of the default gateways for IPv4 and IPv6).

note: this feature uses libvdestack.

#### 2C. run hashdns (in a vde namespace)

Precondition: the same as in 2B.

```
host$ vdens vxvde://
host$ ip addr
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1
   link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: vde0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
   link/ether ae:1f:a2:8e:8b:a5 brd ff:ff:ff:ff:ff:ff
host$ ip link set vde0 up
host$ ip addr add 10.20.30.1/24 dev vde0
host$ ip route add default via 10.20.30.254
host$ ip addr add 2001:1000:2000:3000::1/64 dev vde0
host$ ip addr
2: vde0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
   link/ether ae:1f:a2:8e:8b:a5 brd ff:ff:ff:ff:ff:ff
   inet 10.20.30.1/24 scope global vde0
    valid_lft forever preferred_lft forever
  inet6 2001:1000:2000:3000::1/64 scope global 
    valid_lft forever preferred_lft forever
  inet6 2001:1000:2000:3000:ac1f:a2ff:fe8e:8ba5/64 scope global mngtmpaddr dynamic 
    valid_lft 86380sec preferred_lft 14380sec
  inet6 fe80::ac1f:a2ff:fe8e:8ba5/64 scope link 
    valid_lft forever preferred_lft forever
host$ hashdns -D mydomain.org -r 208.67.220.220
```

(the -r option specifies which DNS will be used by hashdns. If the option is missing, hashdns uses the name server defined in
 /etc/resolv.conf which could not be reachable from the virtual network.)

#### 3. test the hash based name resolution

On a host, far far away on the Internet ;-) type:

```
$ host -t AAAA foo.hash.mydomain.org
foo.hash.mydomain.org has IPv6 address 2001:1000:2000:3000:cb0e:357a:b0b4:8d89
$ host -t AAAA bar.hash.mydomain.org
bar.hash.mydomain.org has IPv6 address 2001:1000:2000:3000:689c:483e:e381:75cf
```

any fully qualified ending in "hash.mydomain.org" is mapped to a *unique* (except for very very rare hash collisions) 
IPv6 address.

## FQDNDHCP

Fqdndhcp  is an IPv6 DHCP server implementation for IPV6 stateful
autoonfiguration.  When fqdndhcp receives a DHCP query including the  fqdn
option (option 39 as defined in RFC4704) it queries the DNS for an AAAA record.
If there is such a record, the IPv6 address is returned to the DHCP client.  

The  configuration  of  the networking nodes (hosts, servers, networked things
		or threads) is very simple in this way, it is sufficient to provide  each
node with its own fully qualified domain name.  It very convenient to use this
tool is together with hashdns to configure  a  network  of servers (Virtual
		machines in Data Services providing IaaS services, Internet of Things or
		Threads environments).

In fact, each node provided with a fully qualified domain name receives from
hashdns  (through  fqdndhcp)  its  corresponding  hash based IPv6 address and
it is reachable by that name without any further configuration.

### fqdndhcp deployment

#### 1. Set up the DNS

fqdndhcp asssigns IPV6 addresses retrieved from the Domain Name
System to hosts, so the DNS must provide the right AAAA records for fqdndhcp to work.

All the required AAAA records can be added by hand, but clearly fqdndhcp has been design to
interoperate with hashdns.

In the following we'll assume that a hashdns server is up and running (as described in the previous sections of this README file).

#### 2A. run fqdndhcp (on a real host)
```
$ fqdndhcp -i eth0
```

#### 2B. run fqdndhcp (on a VDE network)

```
$ fqdndhcp -s vxvde://
```

#### 2C. run fqdndhcp (in a VDE namespace)

Start a VDE namespace (as described above in hashdns section 2C).
```
$ ip link set vde0 up
$ fqdndhcp -v -i vde0 -r 2620:0:ccc::2
```
-r specifies which DNS will be used by fqdndhcp. If the option is 
missing, fqdndhcp uses the name server defined in /etc/resolv.conf which could not be reachable from the virtual network.

#### 3A. test fqdndhcp (running the client on a real host)

Let us consider the scenario of a host (maybe a tiny device/sensor/actuator of the Internet of Things) that need to auto-configure
its address. Stateless auto-configuration is for clients, IoT devices must be servers thus must be provided with well known, globally visible and accessible
names and addresses.

In order to use fqdndhcp, a dhcpv6 client must be configured to send the Fully Qualified Domain Name of the host on its
queries.

In this example isc-dhclient will be used.

Add the following line to /etc/dhcp/dhclient.conf (this path may vary depending on the GNU-Linux distribution used).
```
send fqdn.fqdn "foo.hash.mydomain.org";
```

Now start your dhclient (here we run dhclient by hand, but it works also if dhclient is started by ifup or other
	similar scripts).
```
# dhclient -6 -i eth0
```

dhclient gets the hash generated address for "foo.hash.mydomain.org" and assigns it to eth0:
```
# ip addr
...
2: eth0: ...
   inet6 2001:1000:2000:3000:cb0e:357a:b0b4:8d89/128 scope global 
      valid_lft forever preferred_lft forever
```

(we are currently investigating why the address is stored with an apprent prefix length 128.
 Despite of this incongruence the address is actually working).

#### 3B. test fqdndhcp (running the client in a VDE namespace)

This example uses fqdndhcp to assign an IPv6 address to a namespace. This is a scenario of the Internet of Threads
(IoTh, see [this paper]
 (http://citeseerx.ist.psu.edu/viewdoc/download;jsessionid=433FBC80E8E3D989E29B1888E94EE5EC?doi=10.1.1.682.2256&rep=rep1&type=pdf)).
Namespaces and processes can be regarded as *logical things* so the same concepts about networking designed for the Internet of Things can
be applied to the Internet of Threads, too.

Start a VDE namespace:
```
host$ vdens vxvde://
host$ ip addr
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1
   link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: vde0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
   link/ether be:a1:d7:f6:6e:a5 brd ff:ff:ff:ff:ff:ff
```

Create a minimal dhclient.conf file. The minimal file to support fqdndhcp consists of one line:
```
send fqdn.fqdn "bar.hash.mydomain.org";
```

Start dhclient (the command is somewhat complex just to avoid warning messages due to unwritable files, dhclient has not been
		designed to work in a namespace).
```
$ /sbin/dhclient -6 -cf dhclient.conf -v vde0 -lf dhclient.leases -pf /dev/null
```

(add -d to force dhclient to run as a foreground process and provide a log of the messages sent and received).

dhclient gets the hash generated address for "bar.hash.mydomain.org" and assigns it to vde0:
```
...
2: vde0: ...
   inet6 2001:1000:2000:3000:689c:483e:e381:75cf/128 scope global
```

## FQDNDHCP4

The same idea of fqdndhcp can be used in IPV4. Hash based addresses cannot be implemented in IPv4 due to the narrow 
address space provided by four bytes only.
Anyway the ability to provide hosts with IP addresses depending only on their names (fully qualified names) is useful for
network administrators aiming to manage large numbers of hosts (and networking namespaces).
Fqdndhcp4 permits to keep the map of the name to address translation in one file. This information is
neither distributed on several hosts or file
nor duplicated.
Whithout fqdndhcp4, IP addresses need to be configured both on the host (or on the dhcp server) and in the dns server configuration files.

### fqdndhcp4 deployment

#### 1. Set up the DNS

Let us always assume your domain is named "mydomain.org".

Add some A records for each host you want to configure by fqdndhcp4.

```
foo4                   IN      A       10.20.30.100
foo4-mask              IN      A       255.255.255.0
foo4-gw                IN      A       10.20.30.254
bar4                   IN      A       10.20.30.101
bar4-mask              IN      A       255.255.255.0
bar4-gw                IN      A       10.20.30.254
```

( increase the serial number in the SOA record and reload the DNS configuration)

#### 2A. run fqdndhcp4 (on a real host)
```
$ fqdndhcp4 -i eth0
```

#### 2B. run fqdndhcp4 (on a VDE network)

```
$ fqdndhcp4 -s vxvde://
```

#### 2C. run fqdndhcp4 (in a VDE namespace)

Start a VDE namespace (as described above in hashdns section 2C).
```
$ ip link set vde0 up
```
... configure ip address and route so that it is possible to reach the resolver (208.67.220.220 in the example here below).
```
$ fqdndhcp4 -i vde0 -r 208.67.220.220
```
-r specifies which DNS will be used by fqdndhcp. If the option is
missing, fqdndhcp uses the name server defined in /etc/resolv.conf which could not be reachable from the virtual network.

#### 3A. test fqdndhcp4 (running the client on a real host)

Isc-dhclient can be used as descrived for the IPv6 version, just the flag -6 must be omitted.

A simpler dhcp client for fdqn IPv4 autoconfigration is *udhcpc* (provided by busybox).

```
# busybox udhcpc -f -q -F foo4.mydomain.org
# ip addr
...
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
    link/ether aa:bb:cc:dd:ee:00 brd ff:ff:ff:ff:ff:ff
 	  inet 10.20.30.100/24 brd 10.20.30.254 scope global vde0
	     valid_lft forever preferred_lft forever
```

#### 3B. test fqdndhcp (running the client in a VDE namespace)

It very similar to the previous case, just remeber to add the interface name to udhcpc (to override the default value which is eth0).
```
# busybox udhcpc -f -q -F foo4.mydomain.org -i vde0
# ip addr
...
2: vde0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
    link/ether aa:bb:cc:dd:ee:00 brd ff:ff:ff:ff:ff:ff
    inet 10.20.30.100/24 brd 10.20.30.254 scope global vde0
       valid_lft forever preferred_lft forever
```

#### 3C. self configuration of stacks provided by the libvdestack library.

This is a sketch of the C source code:
```
#include <libvdeplug.h>
...
struct vdestack *stack;
stack = vde_addstack("vxvde://", NULL);
int fd;
...
vde_stackcmd(stack,
		"/bin/busybox ip link set vde0 up;"
		"/bin/busybox udhcpc -q -F bar4.mydomain.org -i vde0")
fd = vde_msocket(stack, AF_INET, SOCK_STREAM, 0);
...
```

## AUX FILES

This source package includes some auxiliary files intended as hints for system administrators 
aiming to install hashdns and fqdndhcp{4} in their systems/data centers. 
These files may need some editing to fit the actual GNU-Linux distribution and 
infrastructure.

### ifupdown

Files in the *aux-files/ifupdown* directory enable a very simple and strightforward way to configure
network interfaces using the ifup/ifdown commands and fqdndhcp (IPv6).

#### 1. install the ifupdown support
```
# cp aux-files/ifupdown/if-up.d/fqdndhcp /etc/network/if-up.d/fqdndhcp
# cp aux-files/ifupdown/if-down.d/fqdndhcp /etc/network/if-down.d/fqdndhcp
```

#### 2. edit /etc/network/interfaces

For example, if eth0 has to be configured by fhdndhcp the configuration section is:
```
iface tap0 inet6 manual
  fqdndhcp "foo.mydomain.org"
```
... that's all.

### udhcpc configuration script

The standard udhcpc script (/etc/udhcpc/default.script) has been designed to configure
the real interfaces of a host. It does not work properly on network namespaces as it
tries to update system global configurations (e.g. resolvconf).

aux-files/udhcpc/dhcpscript is a minimal script suitable for namespaces (credit: 
this script is a modified version of the udhcp sample script by Gabriel Somlo).

It can be installed (for example) in /usr/local/bin
```
# cp aux-files/udhcpc/dhcpscript /usr/local/bin/dhcpscript
```
and then use it in this way
```
$ busybox udhcp -s /usr/local/bin/dhcpscript
