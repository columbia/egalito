#!/bin/bash
mkdir tmp 2>/dev/null

LD_LIBRARY_PATH=../../src ../../app/etshell >/dev/null <<EOF
parse ../../src/ex/detectnull
detectnull
generate tmp/detectnull.o
EOF
gcc tmp/detectnull.o ../example/detectnullfail.c -o tmp/detectnull
tmp/detectnull | grep -q 'egalito null ptr check failed'
if [ "$?" = 0 ]; then
    echo test passed
else
    echo test failed!
fi
