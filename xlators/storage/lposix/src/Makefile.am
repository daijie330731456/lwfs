
xlator_LTLIBRARIES = lposix.la
xlatordir = $(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/storage

lposix_la_LDFLAGS = -module -avoidversion

lposix_la_SOURCES = lposix.c lposix-helper.c
lposix_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la 

noinst_HEADERS = lposix.h 

AM_CFLAGS = -fPIC -fno-strict-aliasing -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -D$(GF_HOST_OS) -Wall \
	-I$(top_srcdir)/liblwfs/src -shared -nostartfiles \
	$(GF_CFLAGS)

CLEANFILES = 

