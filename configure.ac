
AC_INIT
AM_INIT_AUTOMAKE(meanwhile-gaim, 0.79)

RELEASE=1
AC_SUBST(RELEASE)

AC_PREREQ([2.50])

AC_PROG_CC
AC_PROG_LIBTOOL
LIBTOOL="$LIBTOOL --silent"
AC_PROG_INSTALL

AC_HEADER_STDC
AC_HEADER_SYS_WAIT


AC_C_CONST
AC_STRUCT_TM


AC_ARG_ENABLE(debug, [  --enable-debug	  compile with debugging support],,enable_debug=no)
if test "$enable_debug" = yes; then
   AC_DEFINE(DEBUG, 1, [Define if debugging is enabled.])
fi


CFLAGS="$CFLAGS -Wall -Werror"
AC_SUBST(CFLAGS)



dnl Check for Gaim
PKG_CHECK_MODULES(GAIM, gaim,
[
	AC_DEFINE(HAVE_GAIM, 1, [Define if we've found gaim.])
])

AC_SUBST(GAIM_CFLAGS)



AM_PATH_GLIB_2_0(2.0.0,,AC_MSG_ERROR([
*** GLib 2.0 is required.]))

AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)


dnl Check for Meanwhile includes
AC_ARG_WITH(meanwhile-includes, [  --with-meanwhile-includes=DIR
                          Compile the Gaim plugin against Meanwhile includes in DIR ], [ac_meanwhile_includes="$withval"], [ac_meanwhile_includes="no"])
MEANWHILE_INCLUDES="-I$includedir"
if test "$ac_meanwhile_includes" != "no"; then
	MEANWHILE_INCLUDES="-I$ac_meanwhile_includes"
fi
CPPFLAGS_save="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $MEANWHILE_INCLUDES $GLIB_CFLAGS"
AC_CHECK_HEADER(meanwhile/meanwhile.h, [meanwhileincludes=yes])
CPPFLAGS="$CPPFLAGS_save"
AC_SUBST(MEANWHILE_INCLUDES)


dnl check for Meanwhile library
AC_ARG_WITH(meanwhile-libs, [  --with-meanwhile-libs=DIR
                          Compile the Gaim plugin against the Meanwhile libs in DIR], [ac_meanwhile_libs="$withval"], [ac_meanwhile_libs="no"])
MEANWHILE_LIBS="-L$libdir"
if test "$ac_meanwhile_libs" != "no"; then
    MEANWHILE_LIBS="-L$ac_meanwhile_libs"
fi
MEANWHILE_LIBS="$MEANWHILE_LIBS -lmeanwhile"
AC_CHECK_LIB(meanwhile, mwSession_new, [meanwhile=yes], , $MEANWHILE_LIBS $GLIB_LIBS)
AC_SUBST(MEANWHILE_LIBS)


AC_OUTPUT([Makefile src/Makefile pixmaps/Makefile meanwhile-gaim.spec])

