stubbyconfdir = $(sysconfdir)/stubby
dist_stubbyconf_DATA = stubby.conf.example
dist_sbin_SCRIPTS = stubby-setdns-macos.sh
SUBDIRS=src

install-data-hook:
	test -f ${stubbyconfdir}/stubby.conf || \
		${INSTALL_DATA} ${srcdir}/stubby.conf.example ${stubbyconfdir}/stubby.conf
