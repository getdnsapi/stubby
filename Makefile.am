stubbyconfdir = $(sysconfdir)/stubby
dist_stubbyconf_DATA = stubby.yml.example
if ON_MACOS
dist_sbin_SCRIPTS = stubby-setdns-macos.sh
endif
if ON_WINDOWS
CONFIG_FILE = stubby.yml.windows
else
CONFIG_FILE = ${srcdir}/stubby.yml.example
endif
SUBDIRS=src

stubby.yml.windows: ${srcdir}/stubby.yml.example
	sed 's/$$'"/`echo \\\r`/" $< > $@

install-data-hook: $(CONFIG_FILE)
	test -f ${stubbyconfdir}/stubby.yml || \
		${INSTALL_DATA} $(CONFIG_FILE) ${stubbyconfdir}/stubby.yml
