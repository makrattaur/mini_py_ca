#!/bin/sh

pip3 download -r requirements.txt -d offline_deps

if [ ! -d offline_packs ] ; then
	mkdir offline_packs
fi

currentVer="$(git rev-parse --short HEAD)"
tar jcvf "offline_packs/mca_${currentVer}.tar.bz2" dist/mini_py_ca-0.0.1+${currentVer}* offline_deps install_offline.sh


