# 1、Install libtpms

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
lcov -d ./src -c -o result.info -rc lcov_branch_coverage=1
lcov -r result.info "/usr/*" "*/src/tpm12/*" -o result.info -rc branch_coverage=1
genhtml -o result result.info
```



# 2、Install swtpm

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
lcov -d ./src -c -o result.info -rc lcov_branch_coverage=1
lcov -r result.info "/usr/*" -o result.info -rc branch_coverage=1
genhtml -o result result.info
```


## 2.1、installation failure：
### 1. no libtpms.pc found
Find the path of libtpms.pc: find /usr -name libtpms.pc, add the corresponding path to the variable PKG_CONFIG_PATH according to the settings of the search result, and then re-execute autogen.sh.

```
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
```

### 2. checking for TPMLIB_ChooseTPMVersion in -ltpms... no和configure: error: "libtpms 0.6 or later is required"
Check if the symbol exists by nm -D /usr/local/lib/libtpms.so | grep “TPMLIB_ChooseTPMVersion”, and also check the config.log to see the details of the error.### 3. 报错configure: error: "Is libjson-glib-dev/json-glib-devel installed? -- could not get cflags"
install json-glib：yum install -y json-glib json-glib-devel
or source code installation json-glib：https://download.gnome.org/sources/json-glib/

```
wget https://download.gnome.org/sources/json-glib/1.0/json-glib-1.0.0.tar.xz
tar -xvf json-glib-1.0.0.tar.xz
cd json-glib-1.0.0
./configure --prefix=/usr/local
make -j$(nproc)
make install
```

# 3. swtpm emulates the basic TPM functions
## Setting the TPM_PATH environment variable can be an alternative to the command line parameter -- tpmstate dir=<dir>

```
export TPM_PATH=/tmp/swtpm
mkdir -p $TPM_PATH

```

## 1. Start the process via swtpm cuse to emulate a tpm device, compiling swtpm requires the addition of the compilation parameter --with-cuse=yes

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
## 2. Emulate a tpm device by starting the process with swtpm chardev, this way the emulated device will come with tpmrm0

```
mkdir -p /tmp/swtpm
swtpm_setup --tpmstate /tmp/swtpm --tpm2 --createek --create-ek-cert --create-platform-cert --lock-nvram
swtpm chardev --tpmstate dir=/tmp/swtpm --tpm2 --vtpm-proxy --log file=/tmp/swtpm.log,level=20 &
export TPM2TOOLS_TCTI=device:/dev/tpm0
tpm2_startup -c
tpm2_startup
```
## 3. Start the process via the swtpm socket

```
mkdir -p /tmp/swtpm
swtpm_setup --tpmstate /tmp/swtpm --tpm2 --vmid test:11111111-2222-3333-4444-555555555555 --logfile /tmp/swtpm.log --createek --create-ek-cert --create-platform-cert --lock-nvram --not-overwrite --pcr-banks sha1
swtpm socket --tpmstate dir=/tmp/swtpm --tpm2 --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags not-need-init --log file=/tmp/swtpm.log,level=20 &
export TPM2TOOLS_TCTI=swtpm:port=2321
tpm2_startup -c
tpm2_startup
```



