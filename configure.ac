
AC_INIT
AM_INIT_AUTOMAKE(gaim-meanwhile, 1.0.2)

AC_PREREQ([2.50])

AC_PROG_CC

AC_DISABLE_STATIC
AC_PROG_LIBTOOL
LIBTOOL="$LIBTOOL --silent"

AC_PROG_INSTALL

AC_HEADER_STDC
AC_HEADER_SYS_WAIT

AC_C_CONST
AC_STRUCT_TM


# for the gaim version requirements, the lower and upper bounds
GAIM_VER=1.0.0
GAIM_CAP=2.0.0
AC_SUBST(GAIM_VER)
AC_SUBST(GAIM_CAP)


PKG_CONFIG_PATH="$PKG_CONFIG_PATH:/usr/local/lib/pkgconfig"
export PKG_CONFIG_PATH


AC_ARG_ENABLE(debug, [  --enable-debug	  compile with debugging support],,enable_debug=no)
if test "$enable_debug" = yes; then
   AC_DEFINE(DEBUG, 1, [Define if debugging is enabled.])
fi







dnl Check for Gaim
PKG_CHECK_MODULES(GAIM, gaim,
[
	AC_DEFINE(HAVE_GAIM, 1, [Define if we've found gaim.])
])

AC_SUBST(GAIM_CFLAGS)



dnl Check for Meanwhile
PKG_CHECK_MODULES(MEANWHILE, meanwhile,
[
	AC_DEFINE(HAVE_MEANWHILE, 1, [Define if we've found meanwhile.])
])

AC_SUBST(MEANWHILE_CFLAGS)
AC_SUBST(MEANWHILE_LIBS)



AM_PATH_GLIB_2_0(2.0.0,,AC_MSG_ERROR([
*** GLib 2.0 is required.]))

AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

AC_OUTPUT([Makefile src/Makefile pixmaps/Makefile gaim-meanwhile.spec dist/Makefile])


