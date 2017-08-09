#!/bin/bash

date

timeout 1600 env EGALITO_DEBUG=/dev/null LD_LIBRARY_PATH=../../src ../../app/etshell >& hello2.txt <<EOF
parse ../../src/ex/hello-musl-static-q
inject ../../src/libaddon.so
log generate 1
bin hello2.bin
EOF
objdump -b binary --adjust-vma=0x400000 -D ./hello2.bin -maarch64 > hello2.dis
entry=`grep "entry point is located at" hello2.txt | cut -d ' ' -f 6`
../../src/binloader hello2.bin $entry | tee >(head -n 1) >(python a2f.py) > /dev/null | cat

date
