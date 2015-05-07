AM_CPPFLAGS = $(LCMAPS_CFLAGS)

AM_LDFLAGS = -avoid-version

plugindir = $(MODULEDIR)

plugin_LTLIBRARIES = \
	liblcmaps_pilot_sub_proxy.la
	
if NEED_PROTOTYPE
extra_SOURCES = lcmaps_plugin_prototypes.h
endif

liblcmaps_pilot_sub_proxy_la_SOURCES = \
	$(extra_SOURCES) \
	lcmaps_pilot_sub_proxy.c \
	lcmaps_pilot_sub_proxy_utils.h \
	lcmaps_pilot_sub_proxy_utils.c

liblcmaps_pilot_sub_proxy_la_LIBADD = $(CRYPTO_LIBS)

install-data-hook:
	(\
	cd $(DESTDIR)$(plugindir); \
	rm -f lcmaps_pilot_sub_proxy.mod; \
	$(LN_S) liblcmaps_pilot_sub_proxy@SHREXT@ lcmaps_pilot_sub_proxy.mod; \
	)
