
xlator_LTLIBRARIES = client.la
xlatordir = $(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/protocol

client_la_LDFLAGS = -module -avoidversion

client_la_SOURCES = client-protocol.c saved-frames.c
client_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la

noinst_HEADERS = client-protocol.h saved-frames.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS) \
	-I$(top_srcdir)/liblwfs/src -shared -nostartfiles $(GF_CFLAGS)

CLEANFILES = 

