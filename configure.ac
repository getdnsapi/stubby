AC_PREREQ([2.68])
AC_INIT([Stubby], [0.1.3], [sara@sinodun.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/stubby.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC([clang gcc])

AC_CHECK_LIB([getdns], [getdns_context_set_trust_anchors_url],,
    [AC_MSG_ERROR([Missing dependency: getdns >= 1.2.0 ])],)
AC_CHECK_HEADER([getdns/getdns_extra.h],,
    [AC_MSG_ERROR([Missing dependency: getdns >= 1.2.0 ])],)
AC_CHECK_FUNCS([getdns_yaml2dict],, [
	AC_LIBOBJ(convert_yaml_to_json)
	AC_LIBOBJ(sbuffer)
	AC_CHECK_LIB([yaml], [yaml_parser_parse],,
	    [AC_MSG_ERROR([Missing dependency: libyaml])])
])
AC_CHECK_HEADERS([assert.h stdio.h stdarg.h])

AC_MSG_CHECKING(whether the C compiler (${CC-cc}) accepts the "format" attribute)
AC_CACHE_VAL(ac_cv_c_format_attribute, [
	ac_cv_c_format_attribute=no
	AC_TRY_COMPILE([
		#include <stdio.h>
		void f (char *format, ...)
		    __attribute__ ((format (printf, 1, 2)));
		void (*pf) (char *format, ...)
		    __attribute__ ((format (printf, 1, 2)));
	], [f ("%s", "str");],
	[ac_cv_c_format_attribute="yes"],
	[ac_cv_c_format_attribute="no"])
])
AC_MSG_RESULT($ac_cv_c_format_attribute)
if test $ac_cv_c_format_attribute = yes; then
	AC_DEFINE(HAVE_ATTR_FORMAT, 1,
	    [Whether the C compiler accepts the "format" attribute])
fi

AC_CANONICAL_HOST
case "${host_is}" in
	cygwin*|mingw*)
		AC_DEFINE(STUBBY_ON_WINDOWS, 1, [Whether the build target is Windows])
		;;
esac

AC_CONFIG_FILES([Makefile
                 src/Makefile])
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
