#!/bin/bash
mkdir -p tmp

ln -s ../../src/libegalito.so
LD_LIBRARY_PATH=../../src EGALITO_DEBUG=/dev/null ../../src/loader \
	../binary/build/cout 2>&1 \
    | tail -n 2 >tmp/cout.out
rm libegalito.so

if [ -z "$(diff cout.expected tmp/cout.out)" ]; then
    echo "test passed"
else
    echo "test failed!"
    exit 1
fi
