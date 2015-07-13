Summary: Pilot-sub-proxy plugin for the LCMAPS authorization framework
Name: lcmaps-plugins-pilot-sub-proxy
Version: 0.0.1
Release: 1%{?dist}
License: ASL 2.0
Group: System Environment/Libraries
URL: https://github.com/lcmaps-plugins/lcmaps-plugins-pilot-sub-proxy
Source0:  https://github.com/lcmaps-plugins/%{name}/archive/%{name}-%{version}.tar.gz
BuildRequires: lcmaps-devel, openssl-devel
Requires: lcmaps%{?_isa} >= 1.5.0-1
# BuildRoot is still required for EPEL5
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

%description
The Local Centre MAPping Service (LCMAPS) is a security middleware
component that processes the users Grid credentials (typically X.509
proxy certificates and VOMS attributes) and maps the user to a local
account based on the site local policy.

This package contains the pilot sub-proxy plugin.

%prep
%setup -q

%build

%configure --disable-static

# The following two lines were suggested by
# https://fedoraproject.org/wiki/Packaging/Guidelines to prevent any
# RPATHs creeping in.
# https://fedoraproject.org/wiki/Common_Rpmlint_issues#unused-direct-shlib-dependency
# to prevent unnecessary linking
%define fixlibtool() sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool\
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool\
sed -i -e 's! -shared ! -Wl,--as-needed\\0!g' libtool

%fixlibtool
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT

make DESTDIR=$RPM_BUILD_ROOT install
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'

# clean up installed documentation files
rm -rf ${RPM_BUILD_ROOT}%{_docdir}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%doc AUTHORS LICENSE NEWS doc/lcmaps-example.db
%{_libdir}/lcmaps/lcmaps_pilot_sub_proxy.mod
%{_libdir}/lcmaps/liblcmaps_pilot_sub_proxy.so
%{_mandir}/man8/lcmaps_pilot_sub_proxy.mod.8*

%changelog
* Mon Jul 13 2015 Mischa Salle <msalle@nikhef.nl> 0.0.1-1
- Initial build.
