bin_PROGRAMS = fusermount-lwfs

fusermount_lwfs_SOURCES = fusermount.c $(CONTRIBDIR)/fuse-lib/mount.c
noinst_HEADERS = mount_util.h

AM_CFLAGS = -Wall -D_FILE_OFFSET_BITS=64 -DFUSE_UTIL $(GF_CFLAGS)

install-exec-hook:
	-chown root $(DESTDIR)$(bindir)/fusermount-lwfs
	chmod u+s $(DESTDIR)$(bindir)/fusermount-lwfs

CLEANFILES =
