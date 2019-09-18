AC_INIT([mod_redirectionio], [1.0.0], [contact@redirection.io])

AC_CHECK_PROG(WGET, [wget], [yes], [no])
AS_IF(test x$WGET = xno,
    AC_MSG_ERROR([wget is required.])
)

AC_CHECK_PROG(TAR, [tar], [yes], [no])
AS_IF(test x$TAR = xno,
    AC_MSG_ERROR([tar is required.])
)

AC_ARG_WITH([nginx_version], [AS_HELP_STRING([--with-nginx-version],
    [nginx version to use])],
    [NGINX_VERSION=$withval], [NGINX_VERSION=])

AS_IF(test x$NGINX_VERSION = x, [
        AC_PATH_PROG([NGINX_BIN],[nginx],[])
        AS_IF(test x$NGINX_BIN = x,
            AC_MSG_ERROR([nginx is required.]), [
                NGINX_VERSION=`${NGINX_BIN} -v 2>&1 | grep -o '[[0-9.]]*\$'`
                NGINX_CONFIGURE=`${NGINX_BIN} -V 2>&1 | grep -oP 'configure arguments: (.*)' | cut -d" " -f3-`
                NGINX_PREFIX=`${NGINX_BIN} -V 2>&1 | grep -oP '\-\-prefix=([[^\s]]*)'| cut -d "=" -f2`
                NGINX_MAKE_TARGET="modules"
            ]
        )
    ], [
        NGINX_CONFIGURE="--with-cc-opt='-march=x86-64 -mtune=generic -O2 -pipe -fno-plt -D_FORTIFY_SOURCE=2' --with-ld-opt='-Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now' --with-debug"
        NGINX_PREFIX="${ac_abs_confdir}/nginx-${NGINX_VERSION}/work"
        NGINX_BIN="./nginx-${NGINX_VERSION}/objs/nginx"
        NGINX_MAKE_TARGET="install"
    ]
)

AC_ARG_WITH([proxy_version], [AS_HELP_STRING([--with-proxy-version],
    [proxy version to output])],
    [PROXY_VERSION=$withval], [PROXY_VERSION=libnginx-mod-redirectionio:dev])

PATCH_FILES=

AC_ARG_ENABLE([debian-header],
    AS_HELP_STRING([--enable-debian-header], [Patch nginx source with the debian header patch.]), [
    PATCH_FILES="$PATCH_FILES patches/debian-headers.patch"
])

# Dependencies
PKG_PROG_PKG_CONFIG
PKG_INSTALLDIR

PKG_CHECK_MODULES([redirectionio], [libredirectionio >= 0.0.1])

# Checks for programs.
AC_PROG_GREP

# Checks for libs
AC_CHECK_LIB(pthread, pthread_create)
AC_CHECK_LIB([m], [cos])

AC_ARG_VAR([nginx_version], [Nginx version to use])

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
AC_SUBST(NGINX_PREFIX)
AC_SUBST(BUILD_MODULES_DIR)
AC_SUBST(NGINX_MAKE_TARGET)

AC_MSG_NOTICE([summary of build options:
    Install prefix:     ${PREFIX}
    NGINX-VERSION:      ${NGINX_VERSION}
    NGINX-CONFIGURE:    ${NGINX_CONFIGURE}
    NGINX-PREFIX:       ${NGINX_PREFIX}
    CFLAGS:             ${CFLAGS}
    LIBS:               ${LIBS}
    MODULE_DIR:         ${MODULE_DIR}
    NGINX_BIN:          ${NGINX_BIN}
])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([nginx-test.conf])
AC_OUTPUT
