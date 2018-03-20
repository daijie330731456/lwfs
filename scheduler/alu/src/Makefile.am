sched_LTLIBRARIES = alu.la
scheddir = $(libdir)/lwfs/$(PACKAGE_VERSION)/scheduler

alu_la_LDFLAGS = -module -avoidversion

alu_la_SOURCES = alu.c
alu_la_LIBADD = $(top_builddir)/liblwfs/src/liblwfs.la

noinst_HEADERS = alu.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(GF_HOST_OS)\
	-I$(top_srcdir)/liblwfs/src -shared -nostartfiles $(GF_CFLAGS)

CLEANFILES = 
