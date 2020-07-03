#!/bin/bash
set -e -x

KEAMA_VERSION=$1

#DISTROS="debian-10 ubuntu-18.04 ubuntu-20.04 fedora-32 centos-7 centos-8"
DISTROS="debian-10 ubuntu-18.04 ubuntu-20.04 centos-7"

for d in $DISTROS; do
    export DISTRO=$d
    vagrant destroy -f || true
    vagrant up
    vagrant ssh -- /vagrant/vagrant-pkg.sh $KEAMA_VERSION
    vagrant destroy -f
    rm -rf $DISTRO
    mkdir $DISTRO
    mv keama/isc-dhcp-keama* $DISTRO/
done
