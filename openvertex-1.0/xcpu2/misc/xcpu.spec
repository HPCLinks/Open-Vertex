Name:       xcpu2
Summary:    Provides a means to remotely execute software on a cluster.
Version:    1.2.1
Release:    1.nsa1
Group:      System Environment/Clustering
URL:        http://sourceforge.net/projects/xcpu
License:    MIT/GPL
Source:     xcpu2-%{version}.tar.gz
BuildRoot:  %{_tmppath}/%{name}-%{version}

%description
Xcpu is a suite for accessing resources, executing jobs and managing nodes
in a cluster configuration. Xcpu contains a set of servers running on remote 
nodes or a head node and a set of client programs and libraries which can be 
used to communicate with the servers or write applications that access them.

%package node
Summary: XCPU server that needs to be installed on every node
Group: System Environment/Clustering

%description node
Xcpu is a suite for accessing resources, executing jobs and managing nodes
in a cluster configuration. Xcpu contains a set of servers running on remote 
nodes or a head node and a set of client programs and libraries which can be 
used to communicate with the servers or write applications that access them.

You should install xcpu-node on every node.

%package devel
Summary: Libraries for developing tools that talk to the xcpu server
Group: Development/Libraries

%description devel
Xcpu is a suite for accessing resources, executing jobs and managing nodes
in a cluster configuration. Xcpu contains a set of servers running on remote 
nodes or a head node and a set of client programs and libraries which can be 
used to communicate with the servers or write applications that access them.

If you want to write your own utilities that talk to the xcpu server, you
need to install this package.

%prep
umask 022

%setup -q -n xcpu2-%{version}

%build
umask 022
%{__make}

%install
umask 022
%{__rm} -rf %{buildroot}
%{__mkdir} $RPM_BUILD_ROOT
%{__mkdir_p} $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
%{__make} install INSTALLPREFIX=$RPM_BUILD_ROOT/usr
%{__make} installman INSTALLPREFIX=$RPM_BUILD_ROOT/usr
%{__make} installscripts INSTALLPREFIX=$RPM_BUILD_ROOT

%clean
%{__rm} -rf %{buildroot}

%post node
chkconfig --add xcpufs

%preun node
chkconfig --del xcpufs

%files
%defattr(-,root,root)
%attr(0755,root,root) %{_bindir}/statfs
%attr(0755,root,root) %{_bindir}/xgetent
%attr(0755,root,root) %{_bindir}/xk
%attr(0755,root,root) %{_bindir}/xps
%attr(0755,root,root) %{_bindir}/xrx
%attr(0755,root,root) %{_bindir}/xstat
%attr(0755,root,root) %{_bindir}/xgroupset
%attr(0755,root,root) %{_bindir}/xuserset
%{_mandir}/man1/xk.1.gz
%{_mandir}/man1/xgetent.1.gz
%{_mandir}/man1/xps.1.gz
%{_mandir}/man1/xrx.1.gz
%{_mandir}/man1/xstat.1.gz
%{_mandir}/man1/xgroupset.1.gz
%{_mandir}/man1/xuserset.1.gz
%{_mandir}/man4/statfs.4.gz

%files node
%defattr(-,root,root)
%attr(0755,root,root) /etc/init.d/xcpufs
%attr(0755,root,root) %{_sbindir}/xcpufs
%{_mandir}/man4/xcpufs.4.gz

%files devel
%defattr(-,root,root)
%{_includedir}/libxauth.h
%{_includedir}/libxcpu.h
%{_includedir}/npclient.h
%{_includedir}/npfs.h
%{_includedir}/spclient.h
%{_includedir}/spfs.h
%{_includedir}/strutil.h
%{_includedir}/xcpu.h
%{_libdir}/libnpclient.a
%{_libdir}/libnpfs.a
%{_libdir}/libspclient.a
%{_libdir}/libspfs.a
%{_libdir}/libstrutil.a
%{_libdir}/libxcpu.a
%{_libdir}/libxauth.a
%{_mandir}/man4/xcpu.4.gz

%changelog
* Sat Jul  5 2008 Greg Kurtzer <gmkurtzer@gmail.com>
- Repackaged from upstream xcpu2 for Caos NSA

* Fri Mar 21 2008 Kevin Tegtmeier <kevint@lanl.gov>
- Cleaned up files manifest, using more rpm macros

* Thu Mar 20 2008 Kevin Tegtmeier <kevint@lanl.gov>
- Added xbootfs, cleaned up specfile for newest patches

* Tue Jun 26 2007 Philip Soltero <psoltero@cs.unm.edu>
- Initial build.

