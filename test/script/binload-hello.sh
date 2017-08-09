#!/bin/bash

date

timeout 1600 env EGALITO_DEBUG=/dev/null LD_LIBRARY_PATH=../../src ../../app/etshell >& hello.txt <<EOF
parse ../../src/ex/hello-musl-static-q
log generate 1
bin hello.bin
EOF
objdump -b binary --adjust-vma=0x400000 -D ./hello.bin -maarch64 > hello.dis
entry=`grep "entry point is located at" hello.txt | cut -d ' ' -f 6`
../../src/binloader hello.bin $entry

#log dsymbol 20
#log dloadtime 20
#log pass 10
date
