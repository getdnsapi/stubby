stubbyconfdir = $(sysconfdir)/stubby
dist_stubbyconf_DATA = stubby.yml.example
dist_sbin_SCRIPTS = stubby-setdns-macos.sh
SUBDIRS=src

install-data-hook:
	test -f ${stubbyconfdir}/stubby.yml || \
		${INSTALL_DATA} ${srcdir}/stubby.yml.example ${stubbyconfdir}/stubby.yml
