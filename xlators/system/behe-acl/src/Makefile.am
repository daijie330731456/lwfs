xlator_LTLIBRARIES = behe-acl.la
xlatordir = $(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/system
behe_acl_la_LDFLAGS = -module -avoidversion
behe_acl_la_SOURCES = behe-acl.c
behe_acl_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la

noinst_HEADERS = behe-acl.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS)\
	-I$(top_srcdir)/liblwfs/src -shared -nostartfiles $(GF_CFLAGS)\
	-L$(xlatordir)/

CLEANFILES =

access-control-compat:
	mkdir -p $(DESTDIR)$(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/features
	rm -rf $(DESTDIR)$(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/features/access-control.so
	ln -s ../system/behe-acl.so $(DESTDIR)$(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/features/access-control.so


install-exec-local: access-control-compat
