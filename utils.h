#ifndef VERBOSE_H
#define VERBOSE_H
#include <stdio.h>

void startlog(char *prog, int use_syslog);
void printlog(int priority, const char *format, ...);
void save_pidfile(char *pidfile, char *cwd);

void packetdump(FILE *f, void *arg,ssize_t len);
void printin6addr(FILE *f, struct in6_addr *addr);

typedef struct f16 {
	  char val[2];
} f16;

typedef struct f32 {
	  char val[4];
} f32;

static inline f16 e16(unsigned long val) {
	  f16 ret={{val >> 8,val}};
		  return ret;
}

static inline f32 e32(unsigned long val) {
	  f32 ret={{val >> 24, val >> 16, val >> 8,val}};
		  return ret;
}

static inline unsigned long d16(f16 val) {
	  return val.val[0] << 8 | val.val[1];
}

static inline unsigned long d32(f32 val) {
	  return val.val[0] << 24 | val.val[1] >> 16 | val.val[2] << 8 | val.val[3];
}

static inline void en32(char *buf, unsigned long l) {
	buf[0]=l>>24;
	buf[1]=l>>16;
	buf[2]=l>>8;
	buf[3]=l;
}

static inline void en16(char *buf, unsigned long l) {
	buf[0]=l>>8;
	buf[1]=l;
}

static inline unsigned long de32(char *buf) {
	return (buf[0]<<24) + (buf[1]<<16) + (buf[2]<<8) + buf[3];
}

static inline unsigned long de16(char *buf) {
	return (buf[0]<<8) + buf[1];
}

#endif
