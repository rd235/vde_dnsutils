#ifndef USTRING_H
#define USTRING_H
#include <string.h>

#define ustrlen(s) strlen((char *)(s))
#define ustrcpy(d,s) strcpy((char *)(d),(const char *)(s))
#define ustrncpy(d,s) strcpy((char *)(d),(n),(const char *)(s))

#endif
