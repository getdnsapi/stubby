bin_PROGRAMS = stubby

if GETDNS_LOCAL
stubby_LDADD = $(top_builddir)/$(getdnslib)
EXTRA_CFLAGS = -I$(top_builddir)/$(getdnsincdir)
endif

AUTOMAKE_OPTIONS = subdir-objects
stubby_SOURCES = stubby.c yaml/convert_yaml_to_json.c sldns/sbuffer.c
stubby_CFLAGS = -DSTUBBYCONFDIR=\"$(sysconfdir)/stubby\" -DRUNSTATEDIR=\"$(runstatedir)\" $(EXTRA_CFLAGS)
