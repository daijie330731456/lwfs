xlator_LTLIBRARIES = trash.la
xlatordir = $(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/testing/features

trash_la_LDFLAGS = -module -avoidversion 

trash_la_SOURCES = trash.c
trash_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la 

noinst_HEADERS = trash.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS)\
	-I$(top_srcdir)/liblwfs/src -shared -nostartfiles $(GF_CFLAGS)

CLEANFILES = 

