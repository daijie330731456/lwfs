xlator_LTLIBRARIES = locks.la
xlatordir = $(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/features

locks_la_LDFLAGS = -module -avoidversion

locks_la_SOURCES = common.c posix.c entrylk.c inodelk.c
locks_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la 

noinst_HEADERS = locks.h common.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -fno-strict-aliasing -D$(GF_HOST_OS) \
	-I$(top_srcdir)/liblwfs/src $(GF_CFLAGS) -shared -nostartfiles

CLEANFILES = 

uninstall-local:
	rm -f $(DESTDIR)$(xlatordir)/posix-locks.so

install-data-hook:
	ln -sf locks.so $(DESTDIR)$(xlatordir)/posix-locks.so