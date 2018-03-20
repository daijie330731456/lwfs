EXTRA_DIST = autogen.sh COPYING INSTALL README AUTHORS THANKS NEWS lwfs.spec

SUBDIRS = argp-standalone liblwfs $(LIBLWFSCLIENT_SUBDIR) xlators scheduler transport auth lwfsd $(GF_BOOSTER_SUBDIR) $(FUSERMOUNT_SUBDIR) doc extras

CLEANFILES = 

gitclean: distclean
	find . -name Makefile.in -exec rm -f {} \;
	find . -name Makefile -exec rm -f {} \;
	find . -name mount.lwfs -exec rm -f {} \;
	rm -fr autom4te.cache
	rm -f missing aclocal.m4 config.h.in config.guess config.sub ltmain.sh install-sh configure depcomp
	rm -fr argp-standalone/autom4te.cache
	rm -f argp-standalone/aclocal.m4 argp-standalone/config.h.in argp-standalone/configure argp-standalone/depcomp argp-standalone/install-sh argp-standalone/missing
