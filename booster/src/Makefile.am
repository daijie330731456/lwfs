ldpreload_LTLIBRARIES = liblwfs-booster.la
ldpreloaddir = $(libdir)/lwfs
noinst_HEADERS = booster_fstab.h booster-fd.h
liblwfs_booster_la_SOURCES = booster.c booster_stat.c booster_fstab.c booster-fd.c
liblwfs_booster_la_CFLAGS = -I$(top_srcdir)/liblwfsclient/src/ -D_GNU_SOURCE -D$(GF_HOST_OS) -fPIC -Wall \
	-pthread $(GF_BOOSTER_CFLAGS) -shared -nostartfiles 
liblwfs_booster_la_CPPFLAGS = -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE  \
	-I$(top_srcdir)/liblwfsclient/src \
	-I$(top_srcdir)/liblwfs/src -DDATADIR=\"$(localstatedir)\" \
	-DCONFDIR=\"$(sysconfdir)/lwfs\" $(ARGP_STANDALONE_CPPFLAGS)

liblwfs_booster_la_LDFLAGS = -module -avoidversion
liblwfs_booster_la_LIBADD =  $(top_builddir)/liblwfs/src/liblwfs.la $(top_builddir)/liblwfsclient/src/liblwfsclient.la

CLEANFILES =

uninstall-local:
	rm -f $(DESTDIR)$(ldpreloaddir)/lwfs-booster.so

install-data-hook:
	ln -sf liblwfs-booster.so $(DESTDIR)$(ldpreloaddir)/lwfs-booster.so
