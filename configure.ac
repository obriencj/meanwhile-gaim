

# version of this package
m4_define(gaim_meanwhile_version,	1.0.2.99)

# release of this package
m4_define(gaim_meanwhile_release,	0)

# lower and upper-bound versions of Meanwhile
m4_define(meanwhile_version_min,	0.4.0)
m4_define(meanwhile_version_max,	0.5.0)

# lower and upper-bound versions of Gaim
m4_define(gaim_version_min,		1.0.0)
m4_define(gaim_version_max,		2.0.0)



AC_INIT
AM_INIT_AUTOMAKE(gaim-meanwhile, gaim_meanwhile_version)

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



# substitutions used in gaim-meanwhile.spec.in
RELEASE=gaim_meanwhile_release
AC_SUBST(RELEASE)

GAIM_MIN=gaim_version_min
GAIM_MAX=gaim_version_max
AC_SUBST(GAIM_MIN)
AC_SUBST(GAIM_MAX)

MEANWHILE_MIN=meanwhile_version_min
MEANWHILE_MAX=meanwhile_version_max
AC_SUBST(MEANWHILE_MIN)
AC_SUBST(MEANWHILE_MAX)



# tell pkgconfig to look in the same prefix we're installing this to,
# as that's likely where gaim will be found if it's not in the default
# pkgconfig path
PREFIX=$ac_default_prefix
if test "$prefix" != "NONE"; then
   PREFIX=$prefix
fi

PKG_CONFIG_PATH="$PKG_CONFIG_PATH":"$PREFIX/lib/pkgconfig"
export PKG_CONFIG_PATH



# debug mode
AC_ARG_ENABLE(debug,
	[  --enable-debug	  compile with debugging support],,
	enable_debug=no)

if test "$enable_debug" = yes; then
   AC_DEFINE(DEBUG, 1, [Define if debugging is enabled.])
fi



# Check for Gaim
PKG_CHECK_MODULES(GAIM,
[gaim >= gaim_version_min gaim < gaim_version_max],
[
	AC_DEFINE(HAVE_GAIM, 1, [Define if we've found gaim.])
])

AC_SUBST(GAIM_CFLAGS)
AC_SUBST(GAIM_LIBS)



# Check for Meanwhile
PKG_CHECK_MODULES(MEANWHILE,
[meanwhile >= meanwhile_version_min meanwhile < meanwhile_version_max],
[
	AC_DEFINE(HAVE_MEANWHILE, 1, [Define if we've found meanwhile.])
])

AC_SUBST(MEANWHILE_CFLAGS)
AC_SUBST(MEANWHILE_LIBS)



# Check for GLib
AM_PATH_GLIB_2_0(2.0.0,,AC_MSG_ERROR([
*** GLib 2.0 is required.]))

AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)



AC_CONFIG_FILES(
	[Makefile dist/Makefile pixmaps/Makefile src/Makefile]
	[gaim-meanwhile.spec]
)

AC_OUTPUT()


# The End.
