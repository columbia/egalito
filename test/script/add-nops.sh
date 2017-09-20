#!/bin/bash
mkdir tmp 2>/dev/null

LD_LIBRARY_PATH=../../src EGALITO_DEBUG=/dev/null:disasm=9 ../../app/etshell >tmp/add-nops.out <<EOF
parse ../../src/ex/hi0
nop-pass main
disass main
EOF

grep '^0x0000' tmp/add-nops.out | diff - add-nops.expected >/dev/null

if [ "$?" = 0 ]; then
    echo test passed
else
    echo test failed!
fi
