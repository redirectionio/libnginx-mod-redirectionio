AC_INIT([mod_redirectionio], [1.0.0], [contact@redirection.io])

AC_CHECK_PROG(NGINX, [nginx], [yes], [no])
AS_IF(test x$NGINX = xno,
    AC_MSG_ERROR([nginx is required.])
)

AC_CHECK_PROG(WGET, [wget], [yes], [no])
AS_IF(test x$WGET = xno,
    AC_MSG_ERROR([wget is required.])
)

AC_CHECK_PROG(TAR, [tar], [yes], [no])
AS_IF(test x$TAR = xno,
    AC_MSG_ERROR([tar is required.])
)

AC_ARG_WITH([version], [AS_HELP_STRING([--with-proxy-version],
    [proxy version to output])],
    [PROXY_VERSION=$withval], [PROXY_VERSION=libnginx-mod-redirectionio:dev])

PATCH_FILES=

AC_ARG_ENABLE([debian-header],
    AS_HELP_STRING([--enable-debian-header], [Patch nginx source with the debian header patch.]), [
    PATCH_FILES="$PATCH_FILES patches/debian-headers.patch"
])

echo x${enable_debian-header}

# Dependencies
PKG_PROG_PKG_CONFIG
PKG_INSTALLDIR

PKG_CHECK_MODULES([redirectionio], [libredirectionio >= 0.0.1])

# Checks for programs.
AC_PROG_GREP

# Checks for libs
AC_CHECK_LIB(pthread, pthread_create)
AC_CHECK_LIB([m], [cos])


NGINX_VERSION=`nginx -v 2>&1 | $ac_cv_path_GREP -o '[[0-9.]]*\$'`
NGINX_CONFIGURE=`nginx -V 2>&1 | grep -oP 'configure arguments: (.*)' | cut -d" " -f3-`
NGINX_PREFIX=`nginx -V 2>&1 | grep -oP '\-\-prefix=([[^\s]]*)'| cut -d "=" -f2`
NGINX_BIN=`which nginx`

BUILD_MODULES_DIR="nginx-${NGINX_VERSION}/objs"
PREFIX="${NGINX_PREFIX:-/etc/nginx}"
CFLAGS="$CFLAGS -Wall -g -std=c99 -DPROXY_VERSION=$PROXY_VERSION $redirectionio_CFLAGS"
LIBS="$LIBS $redirectionio_LIBS"
MODULE_DIR=$NGINX_PREFIX/modules

AC_SUBST(PREFIX)
AC_SUBST(NGINX_VERSION)
AC_SUBST(NGINX_CONFIGURE)
AC_SUBST(MODULE_DIR)
AC_SUBST(CFLAGS)
AC_SUBST(LIBS)
AC_SUBST(PATCH_FILES)
AC_SUBST(NGINX_BIN)
AC_SUBST(BUILD_MODULES_DIR)

AC_MSG_NOTICE([summary of build options:
    Install prefix:     ${PREFIX}
    NGINX-VERSION:      ${NGINX_VERSION}
    NGINX-CONFIGURE:    ${NGINX_CONFIGURE}
    CFLAGS:             ${CFLAGS}
    LIBS:               ${LIBS}
    MODULE_DIR:         ${MODULE_DIR}
])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([nginx-test.conf])
AC_OUTPUT
