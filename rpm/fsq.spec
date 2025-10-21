%define name fsq
%define version %{_version}
%define release %{_release}
%define _etcdir /etc

Summary: File storage queue server, client and library.
Name: %{name}
Version: %{version}
Release: %{release}
Source0: rpm/SOURCES/%{name}-%{version}-%{release}.tar.gz
License: GPLv2
BuildRoot: %{_tmppath}/%{name}-buildroot
BuildArch: x86_64
Vendor: GSI
Packager: Thomas Stibor
Url: http://github.com/tstibor/fsq
Requires: TIVsm-API64 >= 7, lustre-client >= 2.10, ltsm >= 0.9
BuildRequires: systemd, lustre-client >= 2.10

%description
File storage queue server (called fsqd) implements a protocol for receiving data via socket, copy
data to Lustre and finally archive data on TSM server. In addition a file storage queue client
is provided for sending data to the file storage queue server via console commands.

%prep
%autosetup -n %{name}-%{version}-%{release}

%build
%configure --enable-fsqd
%make_build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
mkdir -p %{buildroot}/%{_unitdir}
mkdir -p %{buildroot}/%{_etcdir}/default
make install DESTDIR=%{buildroot}
install -m 644 debian/%{name}.fsqd.service %{buildroot}/%{_unitdir}/%{name}.fsqd.service
install -m 600 debian/fsqd.default %{buildroot}/%{_etcdir}/default/fsqd

%files
%defattr(-,root,root)
%{_mandir}/man1/fsqd.1.*
%{_includedir}/fsq/*.h
%{_bindir}/fsqc
%{_libdir}/libfsqapi.*
%{_sbindir}/fsqd
%{_unitdir}/%{name}.fsqd.service
%{_etcdir}/default/fsqd

%post
%systemd_post %{name}.fsqd.service

%preun
%systemd_preun %{name}.fsqd.service

%postun
%systemd_postun %{name}.fsqd.service

%clean
rm -rf %{buildroot}

%changelog

* Tue 21 Oct 2025 Samuel Hasert <s.hasert@gsi.de> 0.9.5
- Absolute file path resolution to prevent path traversal exploit.

* Fri 2 Aug 2024 Thomas Stibor <t.stibor@gsi.de> 0.9.4-1
- Support for IPv6.

* Wed 21 Jun 2023 Thomas Stibor <t.stibor@gsi.de> 0.9.3-1
- Build fsqbench via separate --enable-benchmark flag.

* Thu 18 May 2023 Thomas Stibor <t.stibor@gsi.de> 0.9.2-2
- Enable sending multiple files within one session in fsqc.

* Tue 21 Mar 2023 Thomas Stibor <t.stibor@gsi.de> 0.9.2-1
- Fix critical bug in write_access function.

* Tue Sep 20 2022 Thomas Stibor <t.stibor@gsi.de> 0.9.1-1
- Build static and shared libraries
- Package required header files

* Tue Sep 13 2022 Thomas Stibor <t.stibor@gsi.de> 0.9.0-7
- Fix unaligned pointer

* Mon Aug 8 2022 Thomas Stibor <t.stibor@gsi.de> 0.9.0-2
- Refactored autoconf build system

* Thu Jul 28 2022 Thomas Stibor <t.stibor@gsi.de> 0.9.0-1
- Initial FSQ server, client and library
- Implement FSQ protocol version 1
