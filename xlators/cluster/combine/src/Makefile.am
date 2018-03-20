xlator_LTLIBRARIES = combine.la
xlatordir = $(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/cluster

combine_la_SOURCES = combine.c combine-helper.c

combine_la_LDFLAGS = -module -avoidversion
combine_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la

noinst_HEADERS = combine.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS) \
        -I$(top_srcdir)/liblwfs/src -shared -nostartfiles $(GF_CFLAGS)

CLEANFILES =

uninstall-local:
	rm -f $(DESTDIR)$(xlatordir)/combine.so

