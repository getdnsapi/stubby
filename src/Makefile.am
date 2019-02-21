bin_PROGRAMS = stubby

AUTOMAKE_OPTIONS = subdir-objects
if WITH_YAML
stubby_SOURCES = stubby.c yaml/convert_yaml_to_json.c sldns/sbuffer.c
else
stubby_SOURCES = stubby.c
endif
AM_CPPFLAGS = -DSTUBBYCONFDIR='"$(sysconfdir)/stubby"' -DRUNSTATEDIR='"$(runstatedir)"'
