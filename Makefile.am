if BUILD_MAC
    MAYBE_MAC = osx
endif
SUBDIRS = src $(MAYBE_MAC)

stubbyconfdir = $(sysconfdir)/stubby
dist_stubbyconf_DATA = stubby.conf.example

install-data-hook:
	test -f ${stubbyconfdir}/stubby.conf || \
		${INSTALL_DATA} ${srcdir}/stubby.conf.example ${stubbyconfdir}/stubby.conf
