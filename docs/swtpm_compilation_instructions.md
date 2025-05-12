# 1、安装libtpms

```
# https://github.com/stefanberger/libtpms/tags
yum install -y libtool m4 automake make openssl-devel
tar -zxvf libtpms-0.9.6.tar.gz
cd libtpms-0.9.6
sh autogen.sh --with-openssl=yes --with-tpm1=no --with-tpm2=yes --prefix=/usr/local # --enable-debug
make -j$(nproc)
make install
# make check
# yum install -y lcov
sh autogen.sh --with-openssl=yes --with-tpm1=no --with-tpm2=yes --enable-test-coverage
make check -j$(nproc)
# 生成覆盖率
lcov -d ./src -c -o result.info -rc lcov_branch_coverage=1
lcov -r result.info "/usr/*" "*/src/tpm12/*" -o result.info -rc branch_coverage=1
genhtml -o result result.info
```



# 2、安装swtpm

```
# https://github.com/stefanberger/swtpm/tags
yum install -y glib2-devel json-glib json-glib-devel libtasn1-devel libseccomp-devel gnutls-devel gnutls-utils fuse-devel
tar -zxvf swtpm-0.9.0.tar.gz
cd swtpm-0.9.0
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
sh autogen.sh --with-openssl=yes --with-cuse=yes --with-gnutls=yes --with-selinux=no --disable-tests --prefix=/usr/local # --enable-debug
make -j$(nproc)
make install
# make check
yum install -y libcmocka-devel socat expect
pip3 install pyyaml
sh autogen.sh --with-openssl=yes --with-cuse=yes --with-gnutls=yes --with-selinux=no --enable-test-coverage
make check -j$(nproc)
# 生成覆盖率
lcov -d ./src -c -o result.info -rc lcov_branch_coverage=1
lcov -r result.info "/usr/*" -o result.info -rc branch_coverage=1
genhtml -o result result.info
```


## 2.1、安装失败：
### 1. 报错no libtpms.pc found
查找libtpms.pc路径：find /usr -name libtpms.pc，根据查找结果设置，在变量PKG_CONFIG_P
ATH添加对应路径，然后重新执行autogen.sh

```
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
```

### 2. 报错checking for TPMLIB_ChooseTPMVersion in -ltpms... no和configure: error: "libtpms 0.6 or later is required"
通过nm -D /usr/local/lib/libtpms.so | grep "TPMLIB_ChooseTPMVersion"查看是否存在该
符号，同时可以查看config.log查看详细报错
### 3. 报错configure: error: "Is libjson-glib-dev/json-glib-devel installed? -- could not get cflags"
安装json-glib：yum install -y json-glib json-glib-devel
或源码安装json-glib：https://download.gnome.org/sources/json-glib/

```
wget https://download.gnome.org/sources/json-glib/1.0/json-glib-1.0.0.tar.xz
tar -xvf json-glib-1.0.0.tar.xz
cd json-glib-1.0.0
./configure --prefix=/usr/local
make -j$(nproc)
make install
```

# 3、swtpm模拟TPM基本功能
## 设置TPM_PATH环境变量可以替代命令行参数--tpmstate dir=<dir>

```
export TPM_PATH=/tmp/swtpm
mkdir -p $TPM_PATH

```

## 1. 通过swtpm cuse启动进程，模拟tpm设备，编译swtpm时需要增加编译参数--with-cuse=yes

```
mkdir -p /tmp/swtpm
swtpm_setup --tpmstate /tmp/swtpm --tpm2 --createek --create-ek-cert --create-platform-cert --lock-nvram
# swtpm_cuse --tpmstate dir=/tmp/swtpm --name tpm0 --tpm2 --log file=/tmp/swtpm.log,level=20
swtpm cuse --tpmstate dir=/tmp/swtpm --tpm2 --name tpm0 --log file=/tmp/swtpm.log,level=20
swtpm_ioctl -i /dev/tpm0
export TPM2TOOLS_TCTI=device:/dev/tpm0
tpm2_startup -c
tpm2_startup
```
## 2. 通过swtpm chardev启动进程，模拟tpm设备，这种方式模拟的设备会带有tpmrm0

```
mkdir -p /tmp/swtpm
swtpm_setup --tpmstate /tmp/swtpm --tpm2 --createek --create-ek-cert --create-platform-cert --lock-nvram
swtpm chardev --tpmstate dir=/tmp/swtpm --tpm2 --vtpm-proxy --log file=/tmp/swtpm.log,level=20 &
export TPM2TOOLS_TCTI=device:/dev/tpm0
tpm2_startup -c
tpm2_startup
```
## 3. 通过swtpm socket启动进程

```
mkdir -p /tmp/swtpm
swtpm_setup --tpmstate /tmp/swtpm --tpm2 --vmid test:11111111-2222-3333-4444-555555555555 --logfile /tmp/swtpm.log --createek --create-ek-cert --create-platform-cert --lock-nvram --not-overwrite --pcr-banks sha1
swtpm socket --tpmstate dir=/tmp/swtpm --tpm2 --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags not-need-init --log file=/tmp/swtpm.log,level=20 &
export TPM2TOOLS_TCTI=swtpm:port=2321
tpm2_startup -c
tpm2_startup
```



