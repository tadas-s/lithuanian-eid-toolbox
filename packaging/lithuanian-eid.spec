%global python3_pkgversion 3

Name:           lithuanian-eid
Version:        0.2.0
Release:        1%{?dist}
Summary:        Lithuanian electronic ID tools

License:        GPL-3.0-only
URL:            https://github.com/tadas-s/lithuanian-eid
Source:         %{url}/archive/v%{version}/lithuanian_eid-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python%{python3_pkgversion}-devel, systemd-rpm-macros
Requires:       opensc >= 0.27, pinentry

%generate_buildrequires
%pyproject_buildrequires


%description
Software suite to use Lithuanian electronic ID via OpenSC for
authentication and electronic signatures.


%prep
%autosetup -p1 -n lithuanian_eid-%{version}


%build
%pyproject_wheel


%install
%pyproject_install
install -D -m 644 support/lteid-server.service %{buildroot}%{_userunitdir}/lteid-server.service
install -D -m 644 support/lteid-toolbox.service %{buildroot}%{_userunitdir}/lteid-toolbox.service
install -D -m 644 support/lt.yoyo.lteid.svg %{buildroot}%{_datadir}/icons/hicolor/48x48/apps/lt.yoyo.lteid.svg
install -D -m 644 support/lt.yoyo.lteid.desktop %{buildroot}%{_datadir}/applications/lt.yoyo.lteid.desktop

%check
%pytest


%post
%systemd_user_post lteid-server.service
%systemd_user_post lteid-toolbox.service


%preun
%systemd_user_preun lteid-server.service
%systemd_user_preun lteid-toolbox.service


%postun
%systemd_user_postun lteid-server.service
%systemd_user_postun lteid-toolbox.service


%files
%doc README.md
%license LICENSE
%{python3_sitelib}/lithuanian_eid/
%{python3_sitelib}/lithuanian_eid-*.dist-info/
%{_bindir}/lteid_server
%{_bindir}/lteid_toolbox
%{_userunitdir}/lteid-server.service
%{_userunitdir}/lteid-toolbox.service
%{_datadir}/icons/hicolor/48x48/apps/lt.yoyo.lteid.svg
%{_datadir}/applications/lt.yoyo.lteid.desktop

%changelog
* Sat Mar 01 2025 Tadas Sasnauskas <tadas@yoyo.lt> - 0.1.0
- First release
