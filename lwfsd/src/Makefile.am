sbin_PROGRAMS = lwfsd

lwfsd_SOURCES = lwfsd.c fetch-spec.c
lwfsd_LDADD = $(top_builddir)/liblwfs/src/liblwfs.la $(GF_LDADD)
lwfsd_LDFLAGS = $(GF_LDFLAGS) $(GF_LWFS_LDFLAGS)
noinst_HEADERS = lwfsd.h

AM_CFLAGS = -fPIC -Wall -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -D$(GF_HOST_OS)\
	-I$(top_srcdir)/liblwfs/src -DDATADIR=\"$(localstatedir)\" \
	-DCONFDIR=\"$(sysconfdir)/lwfs\" $(GF_LWFS_CFLAGS)

CLEANFILES = 

$(top_builddir)/liblwfs/src/liblwfs.la:
	$(MAKE) -C $(top_builddir)/liblwfs/src/ all

uninstall-local:
	rm -f $(DESTDIR)$(sbindir)/lwfs

install-data-local:
	$(INSTALL) -d -m 755 $(DESTDIR)$(localstatedir)/run
	$(INSTALL) -d -m 755 $(DESTDIR)$(localstatedir)/log/lwfs
	rm -f $(DESTDIR)$(sbindir)/lwfs
	ln -s lwfsd $(DESTDIR)$(sbindir)/lwfs
