lib_LTLIBRARIES = liblwfsclient.la
noinst_HEADERS = liblwfsclient-internals.h
liblwfsclient_HEADERS = liblwfsclient.h 
liblwfsclientdir = $(includedir)

liblwfsclient_la_SOURCES = liblwfsclient.c liblwfsclient-dentry.c
liblwfsclient_la_CFLAGS =  -fPIC -Wall
liblwfsclient_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la
liblwfsclient_la_CPPFLAGS = -D_FILE_OFFSET_BITS=64 -D$(GF_HOST_OS) -D__USE_FILE_OFFSET64 -D_GNU_SOURCE -I$(top_srcdir)/liblwfs/src -DDATADIR=\"$(localstatedir)\" -DCONFDIR=\"$(sysconfdir)/lwfs\" $(GF_CFLAGS)
liblwfsclient_la_LDFLAGS = -shared -nostartfiles

CLEANFILES = 

$(top_builddir)/liblwfs/src/liblwfs.la:
	$(MAKE) -C $(top_builddir)/liblwfs/src/ all

