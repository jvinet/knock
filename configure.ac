AC_PREREQ(2.60)
AC_INIT([knock], [0.7.9], [https://github.com/jvinet/knock/issues])
AM_INIT_AUTOMAKE([dist-xz no-dist-gzip foreign subdir-objects])

AC_CONFIG_HEADER([config.h])

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS

AC_ARG_ENABLE([knockd],
  [AS_HELP_STRING([--disable-knockd], [Disable building knockd (requires libpcap) @<:@default=enabled@:>@])])

AC_ARG_ENABLE([getifaddrs],
  [AS_HELP_STRING([--disable-getifaddrs], [Disable using getifaddrs from glib @<:@default=enabled@:>@])])

AS_IF([test "x$enable_knockd" != "xno"], [
  AC_CHECK_LIB([pcap], [pcap_dispatch], ,
    [AC_MSG_ERROR([you need the libpcap library to build knockd])])
])

AS_IF([test "x$enable_getifaddrs" != "xno"], [
  AC_CHECK_FUNC([getifaddrs],
    [AC_DEFINE([HAVE_GETIFADDRS],[],[Use getifaddrs function])],
    [AC_MSG_ERROR([can not find getifaddrs function.])])
])

AM_CONDITIONAL([BUILD_KNOCKD], [test "x$enable_knockd" != "xno"])
AM_CONDITIONAL([USE_GETIFADDRS], [test "x$enable_getifaddrs" != "xno"])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
