xlator_LTLIBRARIES = my-encryption.la
#xlator_PROGRAMS = setup keygen
xlatordir = $(libdir)/lwfs/$(PACKAGE_VERSION)/xlator/ac

LIBS=-lssl -lcrypto -lglib-2.0 -lgmp -lpbc -lbswabe -lpthread

my_encryption_la_LDFLAGS = -module -avoidversion -Wl,-rpath=/usr/local/lib

my_encryption_la_SOURCES = my-encryption.c enc.c dec.c common.c policy_lang.c crypt-common.c
my_encryption_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la 

#setup_SOURCES = setup.c common.c
#keygen_SOURCES = keygen.c common.c policy_lang.c

noinst_HEADERS = my-encryption.h policy_lang.h crypt.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS)\
	-I$(top_srcdir)/liblwfs/src -shared -nostartfiles $(GF_CFLAGS)\
	-I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include \
	-I/usr/include/pbc -I/usr/local/include/pbc -pg 
CLEANFILES = 

