

# version of this package
m4_define(gaim_meanwhile_version,	1.2.8)

# release of this package. 0 for cvs, 1 for release
m4_define(gaim_meanwhile_release,	1)

# lower and upper-bound versions of Meanwhile
m4_define(meanwhile_version_min,	1.0.0)
m4_define(meanwhile_version_max,	2.0.0)

# lower and upper-bound versions of Gaim
m4_define(gaim_version_min,		1.2.0)
m4_define(gaim_version_max,		2.0.0)



AC_INIT
AM_INIT_AUTOMAKE(gaim-meanwhile, gaim_meanwhile_version)

AC_PREREQ([2.50])

AC_DISABLE_STATIC

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
LIBTOOL="$LIBTOOL --silent"

AC_HEADER_STDC



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



# our cute options which end up in config.h
withval="Talk to me"
AC_ARG_WITH(active_msg,
	[ --with-active-msg=["Talk to me"]
                                     define the default active message])
CONF_ACTIVE_MSG=$withval
AC_SUBST(CONF_ACTIVE_MSG)


withval="Not here right now"
AC_ARG_WITH(away_msg,
	[ --with-away-msg=["Not here right now"]
	                             define the default away message])
CONF_AWAY_MSG=$withval
AC_SUBST(CONF_AWAY_MSG)


withval="Please do not disturb me"
AC_ARG_WITH(busy_msg,
	[ --with-busy-msg=["Please do not disturb me"]
				     define the default busy message])
CONF_BUSY_MSG=$withval
AC_SUBST(CONF_BUSY_MSG)


withval=""
AC_ARG_WITH(host,
	[ --with-host=[""]           define the default community host])
CONF_DEFAULT_HOST=$withval
AC_SUBST(CONF_DEFAULT_HOST)


withval=1533
AC_ARG_WITH(port,
	[ --with-port=[1533]         define the default community port])
CONF_DEFAULT_PORT=$withval
AC_SUBST(CONF_DEFAULT_PORT)


withval="ISO-8859-1"
AC_ARG_WITH(client-encoding,
	[ --with-nb-encoding=["ISO-8859-1"]
                                     default encoding for use with NotesBuddy])
CONF_DEFAULT_ENCODING=$withval
AC_SUBST(CONF_DEFAULT_ENCODING)



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

# this isn't the best way to find Gaim's plugin dir, but it's the best
# I could come up with
#GAIM_PLUGIN_DIR=`$PKG_CONFIG gaim --variable=libdir`/gaim
#AC_SUBST(GAIM_PLUGIN_DIR)

#GAIM_PIXMAP_DIR=`$PKG_CONFIG gaim --variable=datadir`/pixmaps/gaim
#AC_SUBST(GAIM_PIXMAP_DIR)



# Check for Meanwhile
PKG_CHECK_MODULES(MEANWHILE,
[meanwhile >= meanwhile_version_min] [meanwhile < meanwhile_version_max],
[
	AC_DEFINE(HAVE_MEANWHILE, 1, [Define if we've found meanwhile.])
])

AC_SUBST(MEANWHILE_CFLAGS)
AC_SUBST(MEANWHILE_LIBS)

MEANWHILE_LIBA=`$PKG_CONFIG meanwhile --variable=libarchive`
AC_SUBST(MEANWHILE_LIBA)

AC_ARG_ENABLE(static-meanwhile,
	[  --enable-static-meanwhile  statically link in Meanwhile],
	meanwhile_static="yes", meanwhile_static="no")

AM_CONDITIONAL(MEANWHILE_STATIC, test $meanwhile_static = yes)



# Check for GLib
PKG_CHECK_MODULES(GLIB,
[glib-2.0 >= 2.0.0],
[
	AC_DEFINE(HAVE_GLIB, 1, [Define if we've found glib.])
])

AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)



# substitutions and generated files
AC_CONFIG_FILES(
	[src/config.h]
	[Makefile dist/Makefile pixmaps/Makefile src/Makefile]
	[gaim-meanwhile.spec]
)

AC_OUTPUT()


#echo
#echo Gaim plugin dir.......... : $GAIM_PLUGIN_DIR
#echo Gaim pixmap dir.......... : $GAIM_PIXMAP_DIR

echo
echo -n "Meanwhile linking mode... : "
if test "$meanwhile_static" = "yes" ; then
   echo "static"
   echo "Meanwhile library...      : $MEANWHILE_LIBA"
else
   echo "dynamic"
fi

echo
echo Default active message... : \"$CONF_ACTIVE_MSG\"
echo Default away message..... : \"$CONF_AWAY_MSG\"
echo Default busy message..... : \"$CONF_BUSY_MSG\"
echo Default community host... : \"$CONF_DEFAULT_HOST\"
echo Default community port... : $CONF_DEFAULT_PORT
echo NotesBuddy encoding...... : \"$CONF_DEFAULT_ENCODING\"
echo
echo configure complete, now run \`make\`
echo

# The End.
