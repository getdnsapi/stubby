AC_PREREQ([2.68])
AC_INIT([Stubby], [0.2.6], [team@getdnsapi.net])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/stubby.c])
AC_CONFIG_HEADERS([config.h])

AC_DEFINE_UNQUOTED([STUBBY_PACKAGE], [PACKAGE], [Stubby package])
AC_DEFINE_UNQUOTED([STUBBY_PACKAGE_STRING], [PACKAGE_STRING], [Stubby package string])

# Autoconf 2.70 will have set up runstatedir. 2.69 is frequently (Debian)
# patched to do the same, but frequently (MacOS) not. So add a with option
# for pid file location, and default it to runstatedir if present.
default_piddir=${runstatedir:-"${localstatedir}/run"}
AC_ARG_WITH([piddir],
  [AS_HELP_STRING([--with-piddir=DIR],
                  [directory for pid files @<:@default=RUNSTATEDIR or LOCALSTATEDIR/run@:>@])],
  [],
  [with_piddir=${default_piddir}])
AC_SUBST([runstatedir], [$with_piddir])

AC_PROG_CC([clang gcc])

AC_CHECK_LIB([getdns], [getdns_context_set_tls_ciphersuites],,
    [AC_MSG_ERROR([Missing dependency: getdns >= 1.5.0 ])],)
AC_CHECK_HEADERS([getdns/getdns_extra.h],,
    [AC_MSG_ERROR([Missing dependency getdns development headers])],)
AC_CHECK_FUNCS([getdns_yaml2dict],, [
	AC_CHECK_LIB([yaml], [yaml_parser_parse],,
	    [AC_MSG_ERROR([Missing dependency: libyaml])])
])
AM_CONDITIONAL([WITH_YAML], [test "x$ac_cv_func_getdns_yaml2dict" = xno])
AC_CHECK_HEADERS([assert.h stdio.h stdarg.h inttypes.h])

AC_MSG_CHECKING(whether the C compiler (${CC-cc}) accepts the "format" attribute)
AC_TRY_COMPILE([
	#include <stdio.h>
	void f (char *format, ...) __attribute__ ((format (printf, 1, 2)));
	void (*pf) (char *format, ...) __attribute__ ((format (printf, 1, 2)));
], [f ("%s", "str");], [
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_ATTR_FORMAT, 1,
	    [Whether the C compiler accepts the "format" attribute])
], [
	AC_MSG_RESULT(no)
])

AC_MSG_CHECKING(whether the C compiler (${CC-cc}) accepts the "unused" attribute)
AC_TRY_COMPILE([
	#include <stdio.h>
	void f (char *u __attribute__((unused)));
], [f ("x");], [
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_ATTR_UNUSED, 1,
	    [Whether the C compiler accepts the "unused" attribute])
], [
	AC_MSG_RESULT(no)
])

AC_CHECK_HEADERS([os/log.h])

build_on_windows="0"
build_on_macos="0"
build_on_unix="0"
AC_CANONICAL_HOST
case "${host_os}" in
cygwin*|mingw*)
	AC_DEFINE(STUBBY_ON_WINDOWS, 1, [Whether the build target is Windows])
	build_on_windows="1"
	;;
darwin*)
	build_on_macos="1"
	;;
*)
	build_on_unix="1"
	;;
esac
AM_CONDITIONAL([ON_WINDOWS], [test $build_on_windows -eq 1])
AM_CONDITIONAL([ON_MACOS], [test $build_on_macos -eq 1])
AM_CONDITIONAL([ON_UNIX], [test $build_on_unix -eq 1])

AC_CONFIG_FILES([Makefile src/Makefile macos/Makefile])

AH_BOTTOM([
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef STUBBY_ON_WINDOWS
# ifndef  _CUSTOM_VSNPRINTF
#  define _CUSTOM_VSNPRINTF
	static inline int _gldns_custom_vsnprintf(
	    char *str, size_t size, const char *format, va_list ap)
	{ int r = vsnprintf(str, size, format, ap)
	; return r == -1 ? _vscprintf(format, ap) : r; }
#  define vsnprintf _gldns_custom_vsnprintf
# endif
# define PRIsz "Iu"
#else
# define PRIsz "zu"
#endif

#ifdef HAVE_ATTR_FORMAT
# define ATTR_FORMAT(archetype, string_index, first_to_check) \
    __attribute__ ((format (archetype, string_index, first_to_check)))
#else /* !HAVE_ATTR_FORMAT */
# define ATTR_FORMAT(archetype, string_index, first_to_check) /* empty */
#endif /* !HAVE_ATTR_FORMAT */

#if defined(__cplusplus)
#  define ATTR_UNUSED(x)
#elif defined(HAVE_ATTR_UNUSED)
#  define ATTR_UNUSED(x)  x __attribute__((unused))
#else /* !HAVE_ATTR_UNUSED */
#  define ATTR_UNUSED(x)  x
#endif /* !HAVE_ATTR_UNUSED */

#ifndef HAVE_GETDNS_YAML2DICT
# define USE_YAML_CONFIG 1
#endif

#define yaml_string_to_json_string        stubby_yaml_string_to_json_string

#define sldns_read_uint16                 stubby_ldns_read_uint16
#define sldns_read_uint32                 stubby_ldns_read_uint32
#define sldns_write_uint16                stubby_ldns_write_uint16
#define sldns_write_uint32                stubby_ldns_write_uint32
#define sldns_write_uint48                stubby_ldns_write_uint48
#define sldns_buffer                      stubby_ldns_buffer
#define sldns_buffer_invariant            stubby_ldns_buffer_invariant
#define sldns_buffer_invariant            stubby_ldns_buffer_invariant
#define sldns_buffer_new                  stubby_ldns_buffer_new
#define sldns_buffer_new_frm_data         stubby_ldns_new_frm_data
#define sldns_buffer_init_frm_data        stubby_ldns_buffer_init_frm_data
#define sldns_buffer_init_vfixed_frm_data stubby_ldns_buffer_init_vfixed_frm_data
#define sldns_buffer_clear                stubby_ldns_buffer_clear
#define sldns_buffer_flip                 stubby_ldns_buffer_flip
#define sldns_buffer_rewind               stubby_ldns_buffer_rewind
#define sldns_buffer_position             stubby_ldns_buffer_position
#define sldns_buffer_set_position         stubby_ldns_buffer_set_position
#define sldns_buffer_skip                 stubby_ldns_buffer_skip
#define sldns_buffer_limit                stubby_ldns_buffer_limit
#define sldns_buffer_set_limit            stubby_ldns_buffer_set_limit
#define sldns_buffer_capacity             stubby_ldns_buffer_capacity
#define sldns_buffer_set_capacity         stubby_ldns_buffer_set_capacity
#define sldns_buffer_reserve              stubby_ldns_buffer_reserve
#define sldns_buffer_at                   stubby_ldns_buffer_at
#define sldns_buffer_begin                stubby_ldns_buffer_begin
#define sldns_buffer_end                  stubby_ldns_buffer_end
#define sldns_buffer_current              stubby_ldns_buffer_current
#define sldns_buffer_remaining_at         stubby_ldns_buffer_remaining_at
#define sldns_buffer_remaining            stubby_ldns_buffer_remaining
#define sldns_buffer_available_at         stubby_ldns_buffer_available_at
#define sldns_buffer_available            stubby_ldns_buffer_available
#define sldns_buffer_write_at             stubby_ldns_buffer_write_at
#define sldns_buffer_set_at               stubby_ldns_buffer_set_at
#define sldns_buffer_write                stubby_ldns_buffer_write
#define sldns_buffer_write_string_at      stubby_ldns_buffer_write_string_at
#define sldns_buffer_write_string         stubby_ldns_buffer_write_string
#define sldns_buffer_write_u8_at          stubby_ldns_buffer_write_u8_at
#define sldns_buffer_write_u8             stubby_ldns_buffer_write_u8
#define sldns_buffer_write_u16_at         stubby_ldns_buffer_write_u16_at
#define sldns_buffer_write_u16            stubby_ldns_buffer_write_u16
#define sldns_buffer_write_u32_at         stubby_ldns_buffer_write_u32_at
#define sldns_buffer_write_u48_at         stubby_ldns_buffer_write_u48_at
#define sldns_buffer_write_u32            stubby_ldns_buffer_write_u32
#define sldns_buffer_write_u48            stubby_ldns_buffer_write_u48
#define sldns_buffer_read_at              stubby_ldns_buffer_read_at
#define sldns_buffer_read                 stubby_ldns_buffer_read
#define sldns_buffer_read_u8_at           stubby_ldns_buffer_read_u8_at
#define sldns_buffer_read_u8              stubby_ldns_buffer_read_u8
#define sldns_buffer_read_u16_at          stubby_ldns_buffer_read_u16_at
#define sldns_buffer_read_u16             stubby_ldns_buffer_read_u16
#define sldns_buffer_read_u32_at          stubby_ldns_buffer_read_u32_at
#define sldns_buffer_read_u32             stubby_ldns_buffer_read_u32
#define sldns_buffer_status               stubby_ldns_buffer_status
#define sldns_buffer_status_ok            stubby_ldns_buffer_status_ok
#define sldns_buffer_printf               stubby_ldns_buffer_printf
#define sldns_buffer_free                 stubby_ldns_buffer_free
#define sldns_buffer_export               stubby_ldns_buffer_export
#define sldns_buffer_copy                 stubby_ldns_buffer_copy

#define gldns_read_uint16                 stubby_ldns_read_uint16
#define gldns_read_uint32                 stubby_ldns_read_uint32
#define gldns_write_uint16                stubby_ldns_write_uint16
#define gldns_write_uint32                stubby_ldns_write_uint32
#define gldns_write_uint48                stubby_ldns_write_uint48
#define gldns_buffer                      stubby_ldns_buffer
#define gldns_buffer_invariant            stubby_ldns_buffer_invariant
#define gldns_buffer_invariant            stubby_ldns_buffer_invariant
#define gldns_buffer_new                  stubby_ldns_buffer_new
#define gldns_buffer_new_frm_data         stubby_ldns_new_frm_data
#define gldns_buffer_init_frm_data        stubby_ldns_buffer_init_frm_data
#define gldns_buffer_init_vfixed_frm_data stubby_ldns_buffer_init_vfixed_frm_data
#define gldns_buffer_clear                stubby_ldns_buffer_clear
#define gldns_buffer_flip                 stubby_ldns_buffer_flip
#define gldns_buffer_rewind               stubby_ldns_buffer_rewind
#define gldns_buffer_position             stubby_ldns_buffer_position
#define gldns_buffer_set_position         stubby_ldns_buffer_set_position
#define gldns_buffer_skip                 stubby_ldns_buffer_skip
#define gldns_buffer_limit                stubby_ldns_buffer_limit
#define gldns_buffer_set_limit            stubby_ldns_buffer_set_limit
#define gldns_buffer_capacity             stubby_ldns_buffer_capacity
#define gldns_buffer_set_capacity         stubby_ldns_buffer_set_capacity
#define gldns_buffer_reserve              stubby_ldns_buffer_reserve
#define gldns_buffer_at                   stubby_ldns_buffer_at
#define gldns_buffer_begin                stubby_ldns_buffer_begin
#define gldns_buffer_end                  stubby_ldns_buffer_end
#define gldns_buffer_current              stubby_ldns_buffer_current
#define gldns_buffer_remaining_at         stubby_ldns_buffer_remaining_at
#define gldns_buffer_remaining            stubby_ldns_buffer_remaining
#define gldns_buffer_available_at         stubby_ldns_buffer_available_at
#define gldns_buffer_available            stubby_ldns_buffer_available
#define gldns_buffer_write_at             stubby_ldns_buffer_write_at
#define gldns_buffer_set_at               stubby_ldns_buffer_set_at
#define gldns_buffer_write                stubby_ldns_buffer_write
#define gldns_buffer_write_string_at      stubby_ldns_buffer_write_string_at
#define gldns_buffer_write_string         stubby_ldns_buffer_write_string
#define gldns_buffer_write_u8_at          stubby_ldns_buffer_write_u8_at
#define gldns_buffer_write_u8             stubby_ldns_buffer_write_u8
#define gldns_buffer_write_u16_at         stubby_ldns_buffer_write_u16_at
#define gldns_buffer_write_u16            stubby_ldns_buffer_write_u16
#define gldns_buffer_write_u32_at         stubby_ldns_buffer_write_u32_at
#define gldns_buffer_write_u48_at         stubby_ldns_buffer_write_u48_at
#define gldns_buffer_write_u32            stubby_ldns_buffer_write_u32
#define gldns_buffer_write_u48            stubby_ldns_buffer_write_u48
#define gldns_buffer_read_at              stubby_ldns_buffer_read_at
#define gldns_buffer_read                 stubby_ldns_buffer_read
#define gldns_buffer_read_u8_at           stubby_ldns_buffer_read_u8_at
#define gldns_buffer_read_u8              stubby_ldns_buffer_read_u8
#define gldns_buffer_read_u16_at          stubby_ldns_buffer_read_u16_at
#define gldns_buffer_read_u16             stubby_ldns_buffer_read_u16
#define gldns_buffer_read_u32_at          stubby_ldns_buffer_read_u32_at
#define gldns_buffer_read_u32             stubby_ldns_buffer_read_u32
#define gldns_buffer_status               stubby_ldns_buffer_status
#define gldns_buffer_status_ok            stubby_ldns_buffer_status_ok
#define gldns_buffer_printf               stubby_ldns_buffer_printf
#define gldns_buffer_free                 stubby_ldns_buffer_free
#define gldns_buffer_export               stubby_ldns_buffer_export
#define gldns_buffer_copy                 stubby_ldns_buffer_copy
])
AC_OUTPUT
