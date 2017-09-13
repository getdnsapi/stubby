stubbyconfdir = $(sysconfdir)/stubby
dist_stubbyconf_DATA = stubby.yaml.example
dist_sbin_SCRIPTS = stubby-setdns-macos.sh
SUBDIRS=src

install-data-hook:
	test -f ${stubbyconfdir}/stubby.yaml || \
		${INSTALL_DATA} ${srcdir}/stubby.yaml.example ${stubbyconfdir}/stubby.yaml
