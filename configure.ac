AC_PREREQ([2.68])
AC_INIT([Stubby], [0.1.3], [willem@nlnetlabs.nl])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/stubby.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC([clang gcc])

AC_CHECK_LIB([getdns], [getdns_yaml2dict],,
	[AC_MSG_ERROR([Missing dependency: getdns >= 1.2.0 ])],)
AC_CHECK_HEADER([getdns/getdns_extra.h],,
	[AC_MSG_ERROR([Missing dependency: getdns >= 1.2.0 ])],)

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
