#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([vde_dnsutils], [0.2], [info@v2.cs.unibo.it])
AM_INIT_AUTOMAKE([foreign dist-bzip2])
AC_CONFIG_SRCDIR([hashdns.c])
AC_CONFIG_HEADERS([config.h])
CFLAGS="$CFLAGS -Wall"

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stddef.h stdlib.h string.h sys/socket.h syslog.h unistd.h])
AC_CHECK_HEADERS([libvdeplug.h], [], 
	[AC_MSG_ERROR([libvdeplug-dev not found])])
AC_CHECK_HEADERS([mhash.h], [], 
	[AC_MSG_ERROR([libmhash-dev not found])])
AC_CHECK_HEADERS([vdestack.h], [], 
	[AC_MSG_ERROR([libvdestack-dev not found])])
AC_CHECK_HEADERS([adns.h], [], 
	[AC_MSG_ERROR([libadns-dev not found])])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([getcwd memset socket strchr strerror strtol])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
