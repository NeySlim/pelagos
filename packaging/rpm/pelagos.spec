# SPDX-License-Identifier: Apache-2.0
# Pelagos rpm for RHEL 9/10, Rocky, AlmaLinux and Fedora. The payload is a self-contained
# venv under /opt/pelagos built by packaging/build-tree.sh, so the rpm python helpers that
# rewrite shebangs, byte-compile or scan the venv for provides are turned off.
%global pelagos_home /opt/pelagos
%global pelagos_user pelagos
%global __brp_mangle_shebangs %{nil}
%global __brp_python_bytecompile %{nil}
%global __brp_python_hardlink %{nil}
%global __brp_check_rpaths %{nil}
%global _build_id_links none
%global debug_package %{nil}
%global __requires_exclude_from ^%{pelagos_home}/.*$
%global __provides_exclude_from ^%{pelagos_home}/.*$
%global _python_bytecompile_extra 0
# RHEL 9 ships Python 3.9 as python3; Pelagos needs 3.12, packaged there as python3.12.
%if 0%{?rhel} == 9
%global pelagos_python /usr/bin/python3.12
%global pelagos_pypkg python3.12
%else
%global pelagos_python /usr/bin/python3
%global pelagos_pypkg python3
%endif
%global pelagos_pyver %(%{pelagos_python} -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo 0)

Name:           pelagos
Version:        %{?pelagos_version}%{!?pelagos_version:0.0.0}
Release:        %{?pelagos_release}%{!?pelagos_release:1}%{?dist}
Summary:        DNS and DHCP management for BIND 9 and Kea
License:        Apache-2.0
URL:            https://github.com/NeySlim/pelagos
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  %{pelagos_pypkg} >= 3.12
BuildRequires:  %{pelagos_pypkg}-pip
BuildRequires:  systemd-rpm-macros
BuildRequires:  bash
BuildRequires:  findutils

Requires:       %{pelagos_pypkg} >= 3.12
Requires:       python(abi) = %{pelagos_pyver}
Requires:       openssl
Requires:       shadow-utils
Requires(pre):  shadow-utils
%{?systemd_requires}
Suggests:       bind
Suggests:       bind-utils
Suggests:       kea

%description
Pelagos manages BIND 9 zones and Kea DHCP subnets, reservations and leases
through a web interface and a REST API, with replication between nodes. The
engines stay the source of truth: zones are read by AXFR and written by signed
dynamic updates, Kea is driven through its control sockets.

This package installs the node (web process and collector) under /opt/pelagos
with its own Python environment. BIND and Kea are not pulled in: install them
from the distribution, from the ISC Cloudsmith repositories (Kea 3.x), or let
"pelagos install" do it.

%prep
%autosetup -n %{name}-%{version}

%build
# Nothing to compile; the venv is assembled in %%install.

%install
PELAGOS_PYTHON=%{pelagos_python} packaging/build-tree.sh %{buildroot} "$PWD"
install -D -m 0644 packaging/systemd/pelagos.service %{buildroot}%{_unitdir}/pelagos.service
install -D -m 0644 packaging/systemd/pelagos-collector.service %{buildroot}%{_unitdir}/pelagos-collector.service
install -D -m 0644 packaging/pelagos.env %{buildroot}%{_sysconfdir}/pelagos/pelagos.env
install -D -m 0755 packaging/bin/pelagos %{buildroot}%{_bindir}/pelagos
# Enabled like the deb; the units only start once node.toml exists (ConditionPathExists).
install -D -m 0644 packaging/systemd/80-pelagos.preset %{buildroot}%{_presetdir}/80-pelagos.preset
install -d -m 0750 %{buildroot}%{_sysconfdir}/pelagos/tls
install -d -m 0750 %{buildroot}%{_sharedstatedir}/pelagos/{audit,pki,backups,plans,locks}
install -d -m 0755 %{buildroot}%{_docdir}/%{name}
install -m 0644 LICENSE NOTICE README.md %{buildroot}%{_docdir}/%{name}/

%pre
getent group %{pelagos_user} >/dev/null || groupadd -r %{pelagos_user}
getent passwd %{pelagos_user} >/dev/null || \
  useradd -r -g %{pelagos_user} -d %{_sharedstatedir}/pelagos -s /sbin/nologin \
    -c "Pelagos DNS/DHCP manager" %{pelagos_user}
exit 0

%post
# Engine groups give access to the rndc key, the include directory and the Kea sockets.
for grp in named bind kea _kea; do
  getent group "$grp" >/dev/null && usermod -a -G "$grp" %{pelagos_user} || :
done
%systemd_post pelagos.service pelagos-collector.service
if [ $1 -eq 1 ] && [ ! -f %{_sysconfdir}/pelagos/node.toml ]; then
  echo "pelagos: installed. Initialize the first node with:" >&2
  echo "    sudo pelagos init --name \$(hostname -s)" >&2
  echo "or join an existing cluster with 'sudo pelagos enroll', then:" >&2
  echo "    sudo systemctl start pelagos pelagos-collector" >&2
fi

%preun
%systemd_preun pelagos.service pelagos-collector.service

%postun
%systemd_postun_with_restart pelagos.service pelagos-collector.service

%files
%license LICENSE
%doc %{_docdir}/%{name}
%{pelagos_home}
%{_bindir}/pelagos
%{_unitdir}/pelagos.service
%{_unitdir}/pelagos-collector.service
%{_presetdir}/80-pelagos.preset
%dir %attr(0750,%{pelagos_user},%{pelagos_user}) %{_sysconfdir}/pelagos
%dir %attr(0750,%{pelagos_user},%{pelagos_user}) %{_sysconfdir}/pelagos/tls
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/pelagos/pelagos.env
%dir %attr(0750,%{pelagos_user},%{pelagos_user}) %{_sharedstatedir}/pelagos
%dir %attr(0750,%{pelagos_user},%{pelagos_user}) %{_sharedstatedir}/pelagos/audit
%dir %attr(0750,%{pelagos_user},%{pelagos_user}) %{_sharedstatedir}/pelagos/pki
%dir %attr(0750,%{pelagos_user},%{pelagos_user}) %{_sharedstatedir}/pelagos/backups
%dir %attr(0750,%{pelagos_user},%{pelagos_user}) %{_sharedstatedir}/pelagos/plans
%dir %attr(0750,%{pelagos_user},%{pelagos_user}) %{_sharedstatedir}/pelagos/locks

%changelog
* Sat Oct 24 2026 Pelagos maintainers <pelagos@example.org> - 0.1.0~dev0-1
- Initial packaging: venv under /opt/pelagos, systemd units, pelagos wrapper.
