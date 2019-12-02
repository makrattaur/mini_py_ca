#!/bin/sh

if [ ! -d source_archives ] ; then
	mkdir source_archives
fi

currentVer="$(git rev-parse --short HEAD)"
git ls-tree --name-only -r --full-name HEAD | tar jcvf "source_archives/source_${currentVer}.tar.bz2" -T -


