Name:           key_manager
Version:        %_version
Release:        linux
Summary:        Key Manager Package
License:        Mulan v2
Source0:        %{name}-%{version}.tar.gz

%description
Secure key management utility written in Rust

# 禁用 debuginfo 和 debugsource 包
%global debug_package %{nil}
%global _enable_debug_packages 0
%undefine _debugsource_template
%undefine _debuginfo_template

%prep
%autosetup -n %{name}-%{version}

%build
export CARGO_HOME=$(pwd)/.cargo
export CARGO_PROFILE_RELEASE_DEBUG=true
cargo build --release

%install
rm -rf %{buildroot}
install -d -m 0755 %{buildroot}/usr/local/key_manager/bin
install -d -m 0755 %{buildroot}/var/log/key_manager

# 安装二进制
install -m 0755 target/release/key_manager %{buildroot}/usr/local/key_manager/bin/
install -m 0755 target/release/key_managerd %{buildroot}/usr/local/key_manager/bin/
# 配置文件
install -m 0600 .env %{buildroot}/usr/local/key_manager/bin/.env

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
%dir /var/log/key_manager

%changelog
