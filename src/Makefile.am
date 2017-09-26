AUTOMAKE_OPTIONS = subdir-objects
LDADD = $(LIBOBJS) $(ALLOCA)
AM_CPPFLAGS = -DSTUBBYCONFDIR=\"$(sysconfdir)/stubby\" -DRUNSTATEDIR=\"$(runstatedir)\"
bin_PROGRAMS = stubby
stubby_SOURCE = stubby.c
