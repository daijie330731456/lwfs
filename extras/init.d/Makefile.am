
EXTRA_DIST = lwfsd-Debian lwfsd-Redhat lwfsd-SuSE lwfs-server.plist

CLEANFILES = 

initdir = @initdir@

$(GF_DISTRIBUTION): 
	$(mkdir_p) $(DESTDIR)$(initdir)	
	$(INSTALL_PROGRAM) lwfsd-$(GF_DISTRIBUTION) $(DESTDIR)$(initdir)/lwfsd

install-exec-local: $(GF_DISTRIBUTION)

install-data-local: 
if GF_DARWIN_HOST_OS
	cp lwfs-server.plist /Library/LaunchDaemons/com.lw.lwfs.plist 
endif
