
xlator_LTLIBRARIES = posix.la
xlatordir = $(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/storage

posix_la_LDFLAGS = -module -avoidversion

posix_la_SOURCES = posix.c posix-helper.c
posix_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la 

noinst_HEADERS = posix.h lustre_quota.h

AM_CFLAGS = -fPIC -fno-strict-aliasing -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -D$(GF_HOST_OS) -Wall \
	-I$(top_srcdir)/liblwfs/src -shared -nostartfiles \
	$(GF_CFLAGS)

CLEANFILES = 

