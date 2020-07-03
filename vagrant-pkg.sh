#!/bin/bash
set -e -x

KEAMA_VERSION=$1

# install deps
if [ -e /etc/debian_version ]; then
    FPM_TARGET=deb
    sudo apt-get update --allow-releaseinfo-change
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ruby ruby-dev rubygems build-essential \
         git wget unzip
else
    FPM_TARGET=rpm

    . /etc/os-release

    # centos 7
    if [ "$ID" == "centos" -a "$VERSION_ID" == "7" ]; then
        sudo yum -y install gcc make rpm-build libffi-devel git wget unzip  centos-release-scl
        sudo yum --enablerepo=centos-sclo-rh -y install rh-ruby23 rh-ruby23-ruby-devel rh-ruby23-rubygems rh-ruby23-rubygem-rake
        source /opt/rh/rh-ruby23/enable
        echo 'source /opt/rh/rh-ruby23/enable' | sudo tee -a /root/.bashrc
    else
        if [ "$ID" == "centos" -a "$VERSION_ID" == "8" ]; then
            sudo ping -c 4 onet.pl
        fi
        sudo dnf -y install --enablerepo=PowerTools ruby ruby-devel rubygems rubygem-rake gcc make rpm-build libffi-devel git wget unzip
    fi
fi
sudo -i gem install --no-document fpm

# cleanup
pushd /vagrant
make clean || true
make distclean || true

# configure
./configure --prefix=/usr


# compile
pushd keama
make

# install to DESTDIR
rm -rf root
mkdir root
export DESTDIR=`pwd`/root
make install


# build package
rm -f isc-dhcp-keama*
fpm -n isc-dhcp-keama -v ${KEAMA_VERSION} \
    --license 'ISC' \
    --vendor 'Internet Systems Consortium, Inc.' \
    --url 'https://gitlab.isc.org/isc-projects/dhcp' \
    --description 'ISC DHCP Kea Migration Assistant' \
    -s dir \
    -t ${FPM_TARGET} \
    -C ${DESTDIR} .


# check package
if [ -e /etc/debian_version ]; then
    sudo dpkg -i isc-dhcp-keama_*_amd64.deb
else
    sudo rpm -i isc-dhcp-keama*rpm
fi
ls -al /usr/sbin/keama
/usr/sbin/keama 2>&1 | grep Usage
