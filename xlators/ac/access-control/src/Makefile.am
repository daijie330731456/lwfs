xlator_LTLIBRARIES = access-control.la
xlatordir = $(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/ac

access_control_la_LDFLAGS = -module -avoidversion 

access_control_la_SOURCES = access-control.c tree.c
access_control_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la 

noinst_HEADERS = access-control.h tree.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS)\
	-I$(top_srcdir)/liblwfs/src -shared -nostartfiles $(GF_CFLAGS)

CLEANFILES = 

