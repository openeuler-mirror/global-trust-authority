%define cli_output_dir        %{_builddir}/%{_source_dir}/target/debug
%define cli_systemd_dir       %{_sysconfdir}/systemd/system

Name:     ra-cli
Version:  %_ra_version
Release:  %_ra_release
Summary:  Global Trust Authority CLI
Summary(zh_CN):  统一远程证明命令行工具
License:  MulanPSL-2.0
Source0: %{_source_dir}.tar.gz
Source1: vendor.tar.gz

Requires: systemd, openssl, tpm2-tss

%description
Global Trust Authority Command Line Interface

%description -l zh_CN
统一远程证明命令行工具

%prep
%setup -q -n %{_source_dir}
cd %{_builddir}
tar -xzf %{SOURCE1} -C %{_builddir}/%{_source_dir}

%build
mkdir -p ./.cargo
cat << EOF > ./.cargo/config.toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

cargo clean

export RUST_MIN_STACK=33554432

CARGO_BUILD_JOBS=4 cargo build -p attestation_cli -p tpm_boot_attester -p tpm_ima_attester -p virt_cca_attester

%install
rm -rf %{buildroot}
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_libdir}
install -d %{buildroot}%{_sysconfdir}/attestation_agent

install -pm 750 %{cli_output_dir}/attestation_cli %{buildroot}%{_bindir}
install -pm 640 config/agent_config.yaml %{buildroot}%{_sysconfdir}/attestation_agent/agent_config.yaml

install -pm 640 %{cli_output_dir}/libtpm_boot_attester.so   %{buildroot}%{_libdir}
install -pm 640 %{cli_output_dir}/libtpm_ima_attester.so    %{buildroot}%{_libdir}
install -pm 640 %{cli_output_dir}/libvirt_cca_attester.so  %{buildroot}%{_libdir}

%files
%config %attr(0640, root, root) %{_sysconfdir}/attestation_agent/agent_config.yaml

%{_bindir}/attestation_cli
%{_libdir}/libtpm_boot_attester.so
%{_libdir}/libtpm_ima_attester.so
%{_libdir}/libvirt_cca_attester.so

%changelog
* Thu Mar 14 2024 Build - 0.0.1
- Package init