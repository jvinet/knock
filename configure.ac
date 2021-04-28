AC_PREREQ(2.60)
AC_INIT([knock], [0.8], [https://github.com/jvinet/knock/issues])
AM_INIT_AUTOMAKE([dist-xz no-dist-gzip foreign subdir-objects])

AC_CONFIG_HEADER([config.h])

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS

AC_ARG_ENABLE([knockd],
  [AS_HELP_STRING([--disable-knockd], [Disable building knockd (requires libpcap) @<:@default=enabled@:>@])])

AS_IF([test "x$enable_knockd" != "xno"], [
  AC_CHECK_LIB([pcap], [pcap_dispatch], ,
    [AC_MSG_ERROR([you need the libpcap library to build knockd])])
])

AM_CONDITIONAL([BUILD_KNOCKD], [test "x$enable_knockd" != "xno"])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
