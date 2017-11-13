#!/bin/bash
mkdir tmp 2>/dev/null

ln -s ../../src/libegalito.so
LD_LIBRARY_PATH=../../src EGALITO_DEBUG=/dev/null ../../src/loader \
	../binary/build/environ \
    >tmp/environ.out 2>&1
rm libegalito.so

grep -q 'done' tmp/environ.out
if [ "$?" = 0 ]; then
    echo test passed
else
    echo test failed!
    exit 1
fi
