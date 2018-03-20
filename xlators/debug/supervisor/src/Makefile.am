
xlator_LTLIBRARIES = supervisor.la
xlatordir = $(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/debug

supervisor_la_LDFLAGS = -module -avoidversion

supervisor_la_SOURCES = supervisor.c server.c proc.c msg_xdr.c
supervisor_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS)\
	-I$(top_srcdir)/liblwfs/src -shared -nostartfiles $(GF_CFLAGS)

CLEANFILES = 

