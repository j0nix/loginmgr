# When we get Source0, wget https://api.github.com/repos/belsebubben/loginmgr/tarball/master into our SOURCE folder, we need below global 
# definitions to automagicly know what that folders naming are after we unpack it...
%global commit0 %(git ls-remote --heads https://github.com/belsebubben/loginmgr.git master | awk ' { print $1 } ')
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7})
%global directory belsebubben-%{name}-%{shortcommit0}

Name:		loginmgr
Epoch:		1
Version:	0.12
Release:	1%{?dist}
BuildArch:	noarch
Summary:	loginmgr command line login / password manager
Group:		Applications/Text
License:	GPLv2
URL:		https://github.com/belsebubben/loginmgr
Source0:	https://api.github.com/repos/belsebubben/loginmgr/tarball/master
BuildRoot: 	%{_tmppath}/%{name}-buildroot
Requires:	python3 
Requires:	python3-cryptography 
Requires:	xclip
Provides:	loginmgr

%global debug_package %{nil}

%description
loginmgr: A simple to use login / password manager for use on the command line.

%prep
# when we untar master, folder will be named as defined by global variable directory
%setup -n %{directory}

%build
# Well hello there...

%install
install -p -D -m 0755 loginmgr.py %{buildroot}%{_bindir}/loginmgr
install -p -D -m 0755 README.md %{buildroot}%{_docdir}/%{name}/README.md

%clean
rm -rf %{buildroot}

%pre
# nothing .. for now

%post
# nothing .. for now

%preun
# nothing .. for now

%postun
# nothing .. for now

%files
%{_bindir}/loginmgr

%doc %{_docdir}/%{name}/README.md

%changelog
* Wed Aug 23 2017 Carl Hartman <https://github.com/belsebubben> - 0.12
- Export funcion

* Fri Aug 18 2017 Carl Hartman <https://github.com/belsebubben> - 0.1
- Inifial build
