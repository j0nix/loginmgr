<<<<<<< HEAD
#git ls-remote https://github.com/belsebubben/loginmgr.git
%global commit0 2ab471f6452a6242549cc924b41ff346a186075a 
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7})
%global directory belsebubben-%{name}-%{shortcommit0}
Name:           loginmgr
Version:        0.11
=======
Name:		loginmgr
Epoch:		1
Version:	0.12
Release:	1%{?dist}
BuildArch:	noarch
>>>>>>> e27090546cf2b1ff125161a370415ad51db128ad
Summary:	loginmgr command line login / password manager
Group:		Applications/Text
Release:	1%{?dist}
License:	GPLv2
URL:		https://github.com/belsebubben/loginmgr
#Source0:	loginmgr.tar.gz
#Source0:	https://api.github.com/repos/belsebubben/loginmgr/tarball/master
BuildArch:	x86_64
BuildRoot: 	%{_tmppath}/%{name}-buildroot
Requires:	python3 
Requires:	python3-cryptography 
Requires:	xclip
Provides:	loginmgr

%global debug_package %{nil}

%description
loginmgr: A simple to use login / password manager for use on the command line.

%prep
%setup -n loginmgr
#%setup -n %{directory}

%build

%install

#mkdir -p -m 0755 doc/man1 $RPM_BUILD_ROOT%{_mandir}/man1
install -p -D -m 0755 loginmgr.py %{buildroot}%{_bindir}/loginmgr
install -p -D -m 0755 README.md %{buildroot}%{_docdir}/%{name}/README.md

%clean
rm -rf $RPM_BUILD_ROOT

%post

%preun

%postun

%files
%{_bindir}/loginmgr
%{_docdir}/%{name}/README.md
#%{_mandir}/man1/loginmgr.1

#%doc README.md

%changelog
* Wed Aug 23 2017 Carl Hartman <https://github.com/belsebubben> - 0.12
- Export funcion

* Fri Aug 18 2017 Carl Hartman <https://github.com/belsebubben> - 0.1
- Inifial build
