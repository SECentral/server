#!/bin/sh
# Shared production/development build; keep policy parsing off the host system.
set -eu
apt-get update -qq
apt-get install --no-install-recommends -y build-essential ca-certificates curl bzip2 flex bison \
  python3-dev python3-venv python3-setuptools python3-wheel cython3 libselinux1-dev
mkdir -p /tmp/policy-tools-src /opt/secentral-policy-tools/licenses
cd /tmp/policy-tools-src
curl --fail --location --retry 3 -o libsepol.tar.gz https://github.com/SELinuxProject/selinux/releases/download/3.11/libsepol-3.11.tar.gz
curl --fail --location --retry 3 -o setools.tar.bz2 https://github.com/SELinuxProject/setools/releases/download/4.6.0/setools-4.6.0.tar.bz2
printf '%s\n' \
  '79f3d2c88f44b7eb5cf54d9792e03232297e17f97a179163f2750099a00f164d  libsepol.tar.gz' \
  '97319aabaf9d4237841ee60dcc9b2f291e73a761f317fd13e293ea2367d5806c  setools.tar.bz2' | sha256sum --check
tar -xzf libsepol.tar.gz
tar -xjf setools.tar.bz2
mv libsepol-3.11 libsepol
make -C libsepol -j2
make -C libsepol install PREFIX=/opt/secentral-policy-tools SHLIBDIR=/opt/secentral-policy-tools/lib
python3 -m venv --system-site-packages /opt/secentral-policy-tools
USERSPACE_SRC=/tmp/policy-tools-src \
  LDFLAGS='-Wl,-rpath,/opt/secentral-policy-tools/lib' \
  /opt/secentral-policy-tools/bin/pip install --no-cache-dir --no-build-isolation --no-deps ./setools
cp libsepol/LICENSE /opt/secentral-policy-tools/licenses/libsepol.txt
cp setools/COPYING* /opt/secentral-policy-tools/licenses/
rm -rf /opt/secentral-policy-tools/include /opt/secentral-policy-tools/lib/libsepol.a /opt/secentral-policy-tools/share
