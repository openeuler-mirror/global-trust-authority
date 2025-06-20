%define server_source_dir_name   global-trust-authority
%define server_output_dir        %{_builddir}/%{server_source_dir_name}/target/release
%define server_systemd_dir       %{_sysconfdir}/systemd/system
%define debug_package %{nil}

Name:     ra-server
Version:  %_ra_version
Release:  %_ra_release
Summary:  Global Trust Authority
Summary(zh_CN):  Unified Remote Attestation
License:  MulanPSL-2.0
Source0: %{server_source_dir_name}.tar.gz
Source1: vendor.tar.gz

%description
Global Trust Authority Server, including main process and plugins

%description -l zh_CN
Unified Remote Attestation Server RPM package, including Server main process and plugins


%prep
%setup -q -n %{server_source_dir_name}
cd %{_builddir}
tar -xzf %{SOURCE1} -C %{_builddir}/%{server_source_dir_name}

%build
mkdir -p ./.cargo
[ -f ./.cargo/config.toml ] || cat << EOF > ./.cargo/config.toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

cargo clean

export RUST_MIN_STACK=33554432

CARGO_BUILD_JOBS=$(nproc) cargo build --release -p attestation_service --features rpm_build
CARGO_BUILD_JOBS=$(nproc) cargo build --release -p tpm_boot_verifier
CARGO_BUILD_JOBS=$(nproc) cargo build --release -p tpm_ima_verifier

%install
rm -rf %{buildroot}
mkdir -m 550 -p %{buildroot}%{_bindir}
mkdir -m 550 -p %{buildroot}%{_libdir}
mkdir -m 550 -p %{buildroot}%{_sysconfdir}/attestation_server/
mkdir -m 550 -p %{buildroot}%{_sysconfdir}/attestation_server/export_policy/
chmod 750 %{buildroot}%{_sysconfdir}/attestation_server/export_policy/

install -pm 550 %{server_output_dir}/attestation_service      %{buildroot}%{_bindir}
install -pm 550 %{server_output_dir}/libpolicy.so             %{buildroot}%{_libdir}
install -pm 550 %{server_output_dir}/libkey_management.so     %{buildroot}%{_libdir}
install -pm 550 %{server_output_dir}/libtpm_ima_verifier.so   %{buildroot}%{_libdir}
install -pm 550 %{server_output_dir}/libtpm_boot_verifier.so  %{buildroot}%{_libdir}
install -pm 644 server_config_rpm.yaml                            %{buildroot}%{_sysconfdir}/attestation_server/server_config_rpm.yaml
install -pm 644 logging.yaml                                  %{buildroot}%{_sysconfdir}/attestation_server/logging.yaml
install -pm 644 .env.rpm                                      %{buildroot}%{_sysconfdir}/attestation_server/.env.rpm
install -pm 644 rdb_sql/attestation_service/mysql/mysql_v1.sql         %{buildroot}%{_sysconfdir}/attestation_server/mysql_v1.sql
install -pm 644 export_policy/tpm_ima.rego                                     %{buildroot}%{_sysconfdir}/attestation_server/export_policy/tpm_ima.rego
install -pm 644 export_policy/tpm_boot.rego                                          %{buildroot}%{_sysconfdir}/attestation_server/export_policy/tpm_boot.rego


%files
%config %attr(0640, root, root) %{_sysconfdir}/attestation_server/server_config_rpm.yaml
%config %attr(0640, root, root) %{_sysconfdir}/attestation_server/logging.yaml
%config %attr(0640, root, root) %{_sysconfdir}/attestation_server/.env.rpm
%config %attr(0640, root, root) %{_sysconfdir}/attestation_server/mysql_v1.sql
%dir %attr(0750, root, root) %{_sysconfdir}/attestation_server/
%dir %attr(0750, root, root) %{_sysconfdir}/attestation_server/export_policy/
%config %attr(0640, root, root) %{_sysconfdir}/attestation_server/export_policy/tpm_ima.rego
%config %attr(0640, root, root) %{_sysconfdir}/attestation_server/export_policy/tpm_boot.rego

%attr(0550, root, root) %{_bindir}/attestation_service
%attr(0550, root, root) %{_libdir}/libpolicy.so
%attr(0550, root, root) %{_libdir}/libkey_management.so
%attr(0550, root, root) %{_libdir}/libtpm_boot_verifier.so
%attr(0550, root, root) %{_libdir}/libtpm_ima_verifier.so


%changelog
* Thu Feb 13 2025 Build - 0.0.1
- Package init

