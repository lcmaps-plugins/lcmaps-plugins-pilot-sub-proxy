mandir = $(datadir)/man

man_MANS = man/lcmaps_pilot_sub_proxy.mod.8 \
           man/create_pilot_sub_proxy.sh.1

man_INPUT = man/lcmaps_pilot_sub_proxy.mod.8.in \
            man/create_pilot_sub_proxy.sh.1.in

docdir = $(datadir)/doc/@PACKAGE@-@VERSION@
doc_DATA = lcmaps-example.db
doc_INPUT = lcmaps-example.db.src

CLEANFILES = $(doc_DATA)

EXTRA_DIST = $(doc_INPUT)


# Create lcmaps-example.db from template file
lcmaps-example.db: lcmaps-example.db.src
	@echo Making $@ from template
	@rm -f $@
	@sed 's|@libdir[@]|$(libdir)|g' $< > $@

