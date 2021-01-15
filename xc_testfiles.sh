#!/bin/bash

## setup.sh - create some files for xc copy testing
dir=cptest

mkdir -p ${dir}/subdir
dd bs=1024 count=16 if=/dev/urandom of=${dir}/file16KB
dd bs=1024 count=16 if=/dev/urandom of=${dir}/file1KB
dd bs=1024 count=16 if=/dev/urandom of=${dir}/file32KB
dd bs=1024 count=16 if=/dev/urandom of=${dir}/file6B
dd bs=1048576 count=32 if=/dev/urandom of=${dir}/subdir/file32MB
dd bs=1048576 count=64 if=/dev/urandom of=${dir}/subdir/file64MB

sha1sum $(find ${dir} -type f | sort) >${dir}.sha1sum
