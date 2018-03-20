xlator_LTLIBRARIES = quota.la
xlatordir = $(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/features

quota_la_LDFLAGS = -module -avoidversion

quota_la_SOURCES = quota.c
quota_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la 

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS) \
	-I$(top_srcdir)/liblwfs/src -shared -nostartfiles $(GF_CFLAGS)

CLEANFILES = 

