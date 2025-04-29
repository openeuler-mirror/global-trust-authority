%define server_source_dir_name   ra
%define server_output_dir        %{_builddir}/%{server_source_dir_name}/target/debug

Name:     ra-server
Version:  %_ra_version
Release:  %_ra_release
Summary:  Global Trust Authority
Summary(zh_CN):  Unified Remote Attestation
License:  MulanPSL-2.0
Source0: ra.tar.gz
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

CARGO_BUILD_JOBS=4 cargo build -p attestation_service -p restful -p policy -p rv -p challenge -p config

%install
rm -rf %{buildroot}
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_libdir}

install -pm 751 %{server_output_dir}/attestation_service      %{buildroot}%{_bindir}
install -pm 644 %{server_output_dir}/libpolicy.so             %{buildroot}%{_libdir}
install -pm 644 %{server_output_dir}/librv.so                 %{buildroot}%{_libdir}

%files
%{_bindir}/attestation_service
%{_libdir}/libpolicy.so
%{_libdir}/librv.so


%changelog
* Thu Feb 13 2025 Build - 0.0.1
- Package init