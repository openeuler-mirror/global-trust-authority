%define project_name global-trust-authority
%define output_dir %{_builddir}/%{project_name}-%{version}/target/release

Name:           %{project_name}-key-manager
Version:        %_version
Release:        1
Summary:        Key Manager Package
License:        Mulan v2
Source0:        %{project_name}-%{version}.tar.gz
Source1:        vendor.tar.gz

%description
Secure key management utility written in Rust

# 禁用 debuginfo 和 debugsource 包
%global debug_package %{nil}
%global _enable_debug_packages 0
%undefine _debugsource_template
%undefine _debuginfo_template

%prep
%autosetup -n %{project_name}-%{version} -p1

# 解压 vendor.tar.gz 到源码目录
tar -xzf %{SOURCE1} -C .

mkdir -p ./.cargo
cat << EOF > ./.cargo/config.toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

%build
cargo clean
export RUST_MIN_STACK=33554432
export CARGO_BUILD_JOBS=$(nproc)
export CARGO_PROFILE_RELEASE_DEBUG=1
cargo build --release -p key_managerd

%install
rm -rf %{buildroot}
install -d -m 0755 %{buildroot}/usr/local/key_manager/bin
install -d -m 0755 %{buildroot}/var/log/key_manager

# 安装二进制
install -m 0755 %{output_dir}/key_manager %{buildroot}/usr/local/key_manager/bin/
install -m 0755 %{output_dir}/key_managerd %{buildroot}/usr/local/key_manager/bin/
# 配置文件
install -m 0600 key_manager/.env %{buildroot}/usr/local/key_manager/bin/.env

%postun
# 强制删除安装目录
rm -rf /usr/local/key_manager
# 删除日志目录
rm -rf /var/log/key_manager

%files
%dir /usr/local/key_manager
%dir /usr/local/key_manager/bin
/usr/local/key_manager/bin/key_manager
/usr/local/key_manager/bin/key_managerd
/usr/local/key_manager/bin/.env

%changelog
* Mon Apr 28 2025 fantonghe<fantonghe@huawei.com> - 0.1.0-1
- Package init
