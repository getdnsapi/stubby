if ON_MACOS
    OPTIONAL_BUILD_SUBDIR = osx
endif
SUBDIRS = src $(OPTIONAL_BUILD_SUBDIR)

stubbyconfdir = $(sysconfdir)/stubby
dist_stubbyconf_DATA = stubby.yml.example

if ON_WINDOWS
CONFIG_FILE = stubby.yml.windows
else
CONFIG_FILE = ${srcdir}/stubby.yml.example
endif

stubby.yml.windows: ${srcdir}/stubby.yml.example
	awk "{sub(/$$/,\"\r\")}1" $< > $@

install-data-hook: $(CONFIG_FILE)
	test -f $(DESTDIR)${stubbyconfdir}/stubby.yml || \
		${INSTALL_DATA} $(CONFIG_FILE) $(DESTDIR)${stubbyconfdir}/stubby.yml
	$(INSTALL) -m 755 -d $(runstatedir)