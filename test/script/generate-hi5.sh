#!/bin/bash
mkdir tmp 2>/dev/null

LD_LIBRARY_PATH=../../src EGALITO_DEBUG=/dev/null ../../app/etshell >/dev/null <<EOF
parse ../../src/ex/hi5
reassign
generate tmp/hi5.elf
EOF

chmod +x tmp/hi5.elf
./tmp/hi5.elf > tmp/hi5.out

if [ -z "$(diff hi5.expected tmp/hi5.out)" ]; then
    echo test passed
else
    echo test failed!
fi
