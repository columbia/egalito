#!/bin/bash

date

timeout 1600 env EGALITO_DEBUG=/dev/null LD_LIBRARY_PATH=../../src ../../app/etshell >& firmware.txt <<EOF
parse ../../src/ex/firmware
log generate 1
bin firmware.bin
EOF
objdump -b binary --adjust-vma=0x7400000 -D ./firmware.bin -maarch64 > firmware.dis
entry=`grep "entry point is located at" firmware.txt | cut -d ' ' -f 6`
../../src/binloader firmware.bin $entry

#log dsymbol 20
#log dloadtime 20
#log pass 10
date
