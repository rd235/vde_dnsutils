#ifndef DNSMSGS_H
#define DNSMSGS_H
#include <utils.h>

#define INCLASS 0x0001
#define PTRTAG 0x000c
#define AAAATAG 0x001c
#define ANYTAG 0x00ff
#define AUTHREPLY_FLAGS 0x8400
#define AUTHFAIL_FLAGS 0x8403
#define COPYNAME_TAG 0xC00C

struct dnshead {
	f16 trans_id;
	f16 flags;
	f16 nquery;
	f16 nanswer;
	f16 nauth;
	f16 nadd;
};

struct querytail {
	f16 type;
	f16 class;
};

struct reply {
	f16 shortname;
	f16 type;
	f16 class;
	f32 ttl;
	f16 len;
	char payload[0];
};

/* returns querytype, -1 if it is not a query */
static inline int querytype(f16 flags) {
	int rv = flags.val[0] >> 3;
	return rv < 16 ? rv : -1;
}

/* 1 if this is a query or a reverse query, 0 otherwise (not a query or a status query) */
static inline int isquery01(f16 flags) {
	unsigned int rv = flags.val[0] >> 3;
	return rv < 2;
}
	
#endif
