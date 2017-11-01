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
	awk "{sub(/$$/,\"\r\")}1" $< > $@

install-data-hook: $(CONFIG_FILE)
	test -f $(DESTDIR)${stubbyconfdir}/stubby.yml || \
		${INSTALL_DATA} $(CONFIG_FILE) $(DESTDIR)${stubbyconfdir}/stubby.yml
