#!/bin/bash
mkdir tmp 2>/dev/null

ln -s ../../src/libegalito.so ./libegalito.so || true
EGALITO_DEBUG=/dev/null ../../src/loader ../binary/target/redzone/redzone > tmp/redzone-output.txt

grep -q "\[redzone_output\] 153295" tmp/redzone-output.txt

if [ "$?" = 0 ]; then
    echo test passed
else
    echo test failed!
    exit 1
fi
rm ./libegalito.so
