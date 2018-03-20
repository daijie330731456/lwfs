xlator_LTLIBRARIES = read-ahead.la
xlatordir = $(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/performance

read_ahead_la_LDFLAGS = -module -avoidversion

read_ahead_la_SOURCES = read-ahead.c page.c
read_ahead_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la

noinst_HEADERS = read-ahead.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS)\
	-I$(top_srcdir)/liblwfs/src -shared -nostartfiles $(GF_CFLAGS)

CLEANFILES = 
