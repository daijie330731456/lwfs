
xlator_LTLIBRARIES = stripe.la
xlatordir = $(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/cluster

stripe_la_LDFLAGS = -module -avoidversion

stripe_la_SOURCES = stripe.c
stripe_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la

noinst_HEADERS = stripe.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS)\
	-I$(top_srcdir)/liblwfs/src -shared -nostartfiles $(GF_CFLAGS)

CLEANFILES = 

