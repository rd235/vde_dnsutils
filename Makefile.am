bin_PROGRAMS = hashdns fqdndhcp fqdndhcp4

hashdns_SOURCES = hashdns.c getbaseaddr.c utils.c name_utils.c revdb.c resolv.c

hashdns_LDADD = -lmhash -lvdestack -ladns

fqdndhcp_SOURCES = fqdndhcp.c utils.c name_utils.c resolv.c

fqdndhcp_LDADD = -lvdeplug -ladns

fqdndhcp4_SOURCES = fqdndhcp4.c utils.c name_utils.c resolv.c

fqdndhcp4_LDADD = -lvdeplug -ladns

man_MANS =  hashdns.1 fqdndhcp.1 fqdndhcp4.1
