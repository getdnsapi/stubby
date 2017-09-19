AC_PREREQ([2.68])
AC_INIT([Stubby], [0.1.2], [willem@nlnetlabs.nl])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/stubby.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC([clang gcc])

AC_CHECK_LIB([getdns], [getdns_context_set_logfunc],,
	[AC_MSG_ERROR([Missing dependency: getdns >= 1.1.2 ])],)
AC_CHECK_HEADER([getdns/getdns_extra.h],,
	[AC_MSG_ERROR([Missing dependency: getdns >= 1.1.2 ])],)

is_mac=""
AS_CASE([$target_os],
        [darwin*],
        [
                is_mac="yes"
        ])
AM_CONDITIONAL([BUILD_MAC], [test "$is_mac"])

AC_CONFIG_FILES([Makefile src/Makefile osx/Makefile])

AC_OUTPUT
