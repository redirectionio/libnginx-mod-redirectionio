AC_INIT([mod_redirectionio], [1.0.0], [contact@redirection.io])

AC_ARG_WITH([version], [AS_HELP_STRING([--with-proxy-version],
    [proxy version to output])],
    [PROXY_VERSION=$withval], [PROXY_VERSION=libapache2-mod-redirectionio:dev])

AC_ARG_WITH(
	[apxs2],
	[  --with-apxs=PATH       Use APXS executable.],
	[
		APXS=${withval}
	],)

if test "x$APXS" = "x"; then
    # The user didn't specify the --with-apxs2-option.

    # Search for apxs2 in the specified directories
    AC_PATH_PROG(APXS, apxs,,
        /usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin)

    if test "x$APXS" = "x"; then
         # Didn't find apxs in any of the specified directories.
         # Search for apxs2 instead.
         AC_PATH_PROG(APXS, apxs2,,
             /usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin)
    fi
fi

# Test if $APXS exists and is an executable.
if test ! -x "$APXS"; then
   # $APXS isn't a executable file.
   AC_MSG_ERROR([
Could not find apxs. Please spesify the path to apxs
using the --with-apxs=/full/path/to/apxs option.
The executable may also be named 'apxs2'.
])
fi

# Dependencies
PKG_PROG_PKG_CONFIG
PKG_INSTALLDIR

PKG_CHECK_MODULES([redirectionio], [libredirectionio >= 0.0.1])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CC_C99

# Checks for libs
AC_CHECK_LIB(pthread, pthread_create)
AC_CHECK_LIB([m], [cos])

PREFIX="$($APXS -q prefix)"
PREFIX="${PREFIX:-/usr}"
LDFLAGS="-L$($APXS -q libdir) -L$LIBREDIRECTIONIO_LIB $LDFLAGS"
HTTPD_VERSION="$($APXS -q HTTPD_VERSION)"
CC="$($APXS -q CC)"
CFLAGS="$($APXS -q CFLAGS) $($APXS -q CPPFLAGS) $($APXS -q EXTRA_CPPFLAGS) $($APXS -q EXTRA_CFLAGS) -I$($APXS -q includedir) -I$($APXS -q APR_INCLUDEDIR)"
CFLAGS="$CFLAGS -Wall -g -std=c99 -DPROXY_VERSION=$PROXY_VERSION $redirectionio_CFLAGS"
LIBS="$LIBS $redirectionio_LIBS"
LIBTOOL="$($APXS -q LIBTOOL)"
MODULE_DIR="$($APXS -q exp_libexecdir)"

AC_SUBST(LDFLAGS)
AC_SUBST(CC)
AC_SUBST(CFLAGS)
AC_SUBST(LIBS)
AC_SUBST(LIBTOOL)
AC_SUBST(MODULE_DIR)
AC_SUBST(APXS)

AC_MSG_NOTICE([summary of build options:
    Install prefix: ${PREFIX}
    APXS:           ${APXS}
    HTTPD-VERSION:  ${HTTPD_VERSION}
    C compiler:     ${CC}
    CFLAGS:         ${CFLAGS}
    LDFLAGS:        ${LDFLAGS}
    LIBS:           ${LIBS}
    LIBTOOL:        ${LIBTOOL}
    MODULE_DIR:     ${MODULE_DIR}
])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
