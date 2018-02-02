if ON_MACOS
    OPTIONAL_BUILD_SUBDIR = macos
endif
SUBDIRS = src $(OPTIONAL_BUILD_SUBDIR)

stubbyconfdir = $(sysconfdir)/stubby
dist_stubbyconf_DATA = stubby.yml.example

dist_noinst_DATA = doc/stubby.1.in
dist_man_MANS = stubby.1
dist_doc_DATA = AUTHORS COPYING ChangeLog INSTALL NEWS README.md

%.1 :: doc/%.1.in ; sed -e "s|@ETCDIR@|$(stubbyconfdir)|g" $< > $@


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
	$(INSTALL) -m 755 -d $(DESTDIR)$(runstatedir)