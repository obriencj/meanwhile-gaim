
AC_INIT
AM_INIT_AUTOMAKE(meanwhile-gaim, 0.78)

AC_PREREQ([2.50])

AC_PROG_CC
AC_PROG_LIBTOOL
LIBTOOL="$LIBTOOL --silent"
AC_PROG_INSTALL

AC_HEADER_STDC
AC_HEADER_SYS_WAIT

dnl use the --with-gaim-source option to enable compilation of the gaim plugin
AC_ARG_WITH(gaim-source, [  --with-gaim-source=DIR
			  Compile the Gaim plugin against Gaim sources in DIR ], [ac_gaim_source="$withval"],[ac_gaim_source="no"])
GAIM_INCLUDES=""
AM_CONDITIONAL(GAIM_PLUGIN, test "$ac_gaim_source" != "no")
if test "$ac_gaim_source" != "no"; then
   GAIM_INCLUDES="-I$ac_gaim_source"

   CPPFLAGS_save="$CPPFLAGS"
   CPPFLAGS="$CPPFLAGS $GAIM_INCLUDES"
   AC_CHECK_HEADERS(prpl.h blist.h)
   CPPFLAGS="$CPPFLAGS_save"
   AC_SUBST(GAIM_INCLUDES)
fi


AC_C_CONST
AC_STRUCT_TM

AC_ARG_ENABLE(debug, [  --enable-debug	  compile with debugging support],,enable_debug=no)
if test "$enable_debug" = yes; then
   AC_DEFINE(DEBUG, 1, [Define if debugging is enabled.])
fi

CFLAGS="$CFLAGS -Wall -Werror"
AC_SUBST(CFLAGS)

AM_PATH_GLIB_2_0(2.0.0,,AC_MSG_ERROR([
*** GLib 2.0 is required.]))

AC_SUBST(GLIB_CFLAGS)

AC_OUTPUT([Makefile src/Makefile pixmaps/Makefile meanwhile-gaim.spec])

