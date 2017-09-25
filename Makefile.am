if BUILD_MAC
    MAYBE_MAC = osx
endif
SUBDIRS = src $(MAYBE_MAC)

stubbyconfdir = $(sysconfdir)/stubby
dist_stubbyconf_DATA = stubby.yml.example

install-data-hook:
	test -f ${stubbyconfdir}/stubby.yml || \
		${INSTALL_DATA} ${srcdir}/stubby.yml.example ${stubbyconfdir}/stubby.yml
