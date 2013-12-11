AM_CFLAGS=-g -Wall -pedantic -fno-exceptions

bin_PROGRAMS = knock

man_MANS = doc/knock.1

if BUILD_KNOCKD
sbin_PROGRAMS = knockd
man_MANS += doc/knockd.1
sysconf_DATA = knockd.conf
endif

dist_doc_DATA = README.md TODO ChangeLog COPYING

knock_SOURCES = src/knock.c
knockd_SOURCES = src/knockd.c src/list.c src/list.h

%.1: %.1.in
	sed -e "s/#VERSION#/$(VERSION)/" $< > $@

EXTRA_DIST = doc/knock.1 doc/knock.1.in doc/knockd.1 doc/knockd.1.in knockd.conf
