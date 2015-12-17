AM_CPPFLAGS=-D_DEFAULT_SOURCE
AM_CFLAGS=-g -Wall -pedantic -fno-exceptions -D_BSD_SOURCE

bin_PROGRAMS = knock
man_MANS = doc/knock.1

if BUILD_KNOCKD
sbin_PROGRAMS = knockd
dist_sbin_SCRIPTS = src/knock_helper_ipt.sh
man_MANS += doc/knockd.1
sysconf_DATA = knockd.conf
endif

dist_doc_DATA = README.md TODO ChangeLog COPYING

knock_SOURCES = src/knock.c
knockd_SOURCES = src/knockd.c src/list.c src/list.h src/knock_helper_ipt.sh

%.1: %.1.in
	sed -e "s/#VERSION#/$(VERSION)/" $< > $@

EXTRA_DIST = doc/knock.1 doc/knock.1.in doc/knockd.1 doc/knockd.1.in knockd.conf
CLEANFILES = $(man_MANS)
