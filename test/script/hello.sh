#!/bin/bash
mkdir -p tmp

ln -sf ../../src/libegalito.so
LD_LIBRARY_PATH=../../src EGALITO_DEBUG=/dev/null ../../src/loader \
	../binary/build/hello \
    >tmp/hello.out 2>&1
rm libegalito.so

if [ -z "$(diff hello.expected tmp/hello.out)" ]; then
    echo "test passed"
else
    echo "test failed!"
    exit 1
fi
