# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([LCMAPS plugins pilot sub-proxy], [0.0.1])
AC_CONFIG_MACRO_DIR([project])
AM_INIT_AUTOMAKE([1.6.3 subdir-objects foreign])
AC_CONFIG_SRCDIR([src/lcmaps_plugins_pilot_sub_proxy_config.h.in])

# Notices.
AC_COPYRIGHT([Copyright (c) 2015 FOM-Nikhef
See LICENCE file for details
])
AC_REVISION([$Revision: 1.14 $])

#Environment.
WORKDIR=`pwd`
AC_SUBST(WORKDIR)

DISTBIN=$WORKDIR/../../dist
AC_SUBST(DISTBIN)

# Checks for programs.
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
AC_PROG_INSTALL

# crypto library
AC_CHECK_LIB([crypto], [X509_free],
[
    CRYPTO_LIBS=-lcrypto
    AC_SUBST([CRYPTO_LIBS])
],
[
    AC_MSG_ERROR([cannot find libcrypto])
])

# Set lcmaps variables
AC_LCMAPS_INTERFACE([basic])
if test "x$have_lcmaps_basic_interface" = "xno" ; then
    AC_MSG_FAILURE(["no LCMAPS basic interface found"])
fi

# Checks for LCMAPS plugin prototype using LCMAPS CFLAGS
SAVED_CPPFLAGS=$CPPFLAGS
CPPFLAGS=$LCMAPS_CFLAGS
AC_CHECK_HEADERS([lcmaps/lcmaps_plugin_prototypes.h])
CPPFLAGS=$SAVED_CPPFLAGS
AM_CONDITIONAL([NEED_PROTOTYPE],
	       [test x$ac_cv_header_lcmaps_lcmaps_plugin_prototypes_h != xyes])

dnl allow the setting of a different path for the plug-ins
dnl Makefiles should set the plugindir to $MODULEDIR.
AC_ARG_WITH([moduledir],
  [AS_HELP_STRING([--with-moduledir=path],
    [Specify the install location of the plug-ins])],
[
	AC_SUBST([MODULEDIR], [$withval])
],
[
	AC_SUBST([MODULEDIR], ['${libdir}/lcmaps'])
])

# Find proper shared library extension
eval SHREXT=$shrext_cmds
AC_SUBST(SHREXT)

# Configuration items
AC_CONFIG_HEADERS([src/lcmaps_plugins_pilot_sub_proxy_config.h])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([doc/Makefile])
AC_CONFIG_FILES([doc/man/lcmaps_pilot_sub_proxy.mod.8])
AC_CONFIG_FILES([doc/man/create_pilot_sub_proxy.sh.1])

AC_OUTPUT
