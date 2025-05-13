%define agent_output_dir        %{_builddir}/%{_source_dir}/target/debug
%define agent_systemd_dir       %{_sysconfdir}/systemd/system

Name:     ra-agent
Version:  %_ra_version
Release:  %_ra_release
Summary:  Global Trust Authority
Summary(zh_CN):  Unified Remote Attestation
License:  MulanPSL-2.0
Source0: %{_source_dir}.tar.gz
Source1: vendor.tar.gz

Requires: systemd, openssl, tpm2-tss

%description
Global Trust Authority Agent, including main process and plugins

%description -l zh_CN
Unified Remote Attestation Agent, including main process and plugins

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

CARGO_BUILD_JOBS=4 cargo build -p attestation_agent -p tpm_boot_attester -p tpm_ima_attester

%install
rm -rf %{buildroot}
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_libdir}
install -d %{buildroot}%{agent_systemd_dir}
install -d %{buildroot}%{_sysconfdir}/attestation_agent

install -pm 751 %{agent_output_dir}/attestation_agent         %{buildroot}%{_bindir}
install -pm 644 config/attestation_agent.service              %{buildroot}%{agent_systemd_dir}
install -pm 644 config/agent_config.yaml                      %{buildroot}%{_sysconfdir}/attestation_agent/agent_config.yaml

install -pm 644 %{agent_output_dir}/libtpm_boot_attester.so   %{buildroot}%{_libdir}
install -pm 644 %{agent_output_dir}/libtpm_ima_attester.so    %{buildroot}%{_libdir}

%files
%{_bindir}/attestation_agent
%config %attr(0644, root, root) %{agent_systemd_dir}/attestation_agent.service
%config %attr(0644, root, root) %{_sysconfdir}/attestation_agent/agent_config.yaml

%{_libdir}/libtpm_boot_attester.so
%{_libdir}/libtpm_ima_attester.so

%post
%systemd_post attestation_agent.service
systemctl enable attestation_agent.service >/dev/null 2>&1 || :
systemctl start attestation_agent.service >/dev/null 2>&1 || :

%preun
%systemd_preun attestation_agent.service

%postun
%systemd_postun_with_restart attestation_agent.service

%changelog
* Thu Feb 13 2025 Build - 0.0.1
- Package init