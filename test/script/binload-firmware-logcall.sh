#!/bin/bash

date

timeout 1600 env EGALITO_DEBUG=/dev/null ../../app/etshell >& firmware2.txt <<EOF
parse ../../src/ex/firmware
inject ../../src/libaddon.so
log generate 1
bin firmware2.bin
EOF
objdump -b binary --adjust-vma=0xC400000 -D --disassemble-zeroes ./firmware2.bin -maarch64 > firmware2.dis
entry=`grep "entry point is located at" firmware2.txt | cut -d ' ' -f 6`
../../src/binloader firmware2.bin $entry | tee >(head -n 1) >(python a2f.py) > /dev/null | cat

date
