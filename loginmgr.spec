Name:		loginmgr
Epoch:		1
Version:	0.16
Release:	1%{?dist}
BuildArch:	noarch
Summary:	loginmgr command line login / password manager
Group:		Applications/Text
# The GPL v2
# https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html
License:	GNU GENERAL PUBLIC LICENSE v2
URL:		https://github.com/belsebubben/loginmgr
Source0:	https://github.com/belsebubben/loginmgr/blob/master/loginmgr.py
Source1:	https://github.com/belsebubben/loginmgr/blob/master/README.md

#BuildRequires:    -

Requires:          python3
Requires:          python3-cryptography
Provides:          loginmgr


%description
loginmgr: A simple to use login / password manager for use on the command line.

%prep
#%setup -q
echo "prep"

%build
#make 
echo "Making"

%install
echo "installing"
install -m 0755 -d %{buildroot}%{_bindir}
install -m 0755 -d %{buildroot}%{_docdir}/%{name}
install -p -D -m 0755 %{SOURCE0} %{buildroot}%{_bindir}/loginmgr
install -p -D -m 0755 %{SOURCE1} %{buildroot}%{_docdir}/%{name}/README.md


%pre
echo "pre"

%post
echo "post"

%preun
echo "preun"

%postun
echo "postun"

%files
%{_bindir}/loginmgr
%{_docdir}/%{name}/README.md

%changelog
* Mon Aug 28 2017 Carl Hartman <https://github.com/belsebubben> - 0.16
- Extending import and export with more functionality and warnings.

* Fri Aug 25 2017 Carl Hartman <https://github.com/belsebubben> - 0.15
- Adding import functionality for exported archive (-i flag)

* Wed Aug 23 2017 Carl Hartman <https://github.com/belsebubben> - 0.14
- Filter password from searches

* Wed Aug 23 2017 Carl Hartman <https://github.com/belsebubben> - 0.12
- Export funcion

* Fri Aug 18 2017 Carl Hartman <https://github.com/belsebubben> - 0.1
- Inifial build
