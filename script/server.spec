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
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_libdir}
install -d %{buildroot}%{_sysconfdir}/attestation_server/
install -d %{buildroot}%{_sysconfdir}/attestation_server/export_policy/

install -pm 755 %{server_output_dir}/attestation_service      %{buildroot}%{_bindir}
install -pm 644 %{server_output_dir}/libpolicy.so             %{buildroot}%{_libdir}
install -pm 644 %{server_output_dir}/libkey_management.so     %{buildroot}%{_libdir}
install -pm 644 %{server_output_dir}/libtpm_ima_verifier.so   %{buildroot}%{_libdir}
install -pm 644 %{server_output_dir}/libtpm_boot_verifier.so  %{buildroot}%{_libdir}
install -pm 644 server_config_rpm.yaml                            %{buildroot}%{_sysconfdir}/attestation_server/server_config_rpm.yaml
install -pm 644 logging.yaml                                  %{buildroot}%{_sysconfdir}/attestation_server/logging.yaml
install -pm 644 .env.rpm                                      %{buildroot}%{_sysconfdir}/attestation_server/.env.rpm
install -pm 644 rdb_sql/attestation_service/mysql/mysql_v1.sql         %{buildroot}%{_sysconfdir}/attestation_server/mysql_v1.sql
install -pm 644 export_policy/tpm_ima                                     %{buildroot}%{_sysconfdir}/attestation_server/export_policy/tpm_ima
install -pm 644 export_policy/tpm_boot                                          %{buildroot}%{_sysconfdir}/attestation_server/export_policy/tpm_boot


%files
%config %attr(0644, root, root) %{_sysconfdir}/attestation_server/server_config_rpm.yaml
%config %attr(0644, root, root) %{_sysconfdir}/attestation_server/logging.yaml
%config %attr(0644, root, root) %{_sysconfdir}/attestation_server/.env.rpm
%config %attr(0644, root, root) %{_sysconfdir}/attestation_server/mysql_v1.sql
%config %attr(0644, root, root) %{_sysconfdir}/attestation_server/export_policy/tpm_ima
%config %attr(0644, root, root) %{_sysconfdir}/attestation_server/export_policy/tpm_boot

%{_bindir}/attestation_service
%{_libdir}/libpolicy.so
%{_libdir}/libkey_management.so
%{_libdir}/libtpm_boot_verifier.so
%{_libdir}/libtpm_ima_verifier.so


%changelog
* Thu Feb 13 2025 Build - 0.0.1
- Package init

