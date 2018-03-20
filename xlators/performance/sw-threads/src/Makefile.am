xlator_LTLIBRARIES = sw-threads.la
xlatordir = $(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/performance

sw_threads_la_LDFLAGS = -module -avoidversion 

sw_threads_la_SOURCES = sw-threads.c
sw_threads_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la

noinst_HEADERS = sw-threads.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS)\
	-I$(top_srcdir)/liblwfs/src -shared -nostartfiles $(GF_CFLAGS)

CLEANFILES = 
