#!/bin/bash
mkdir -p tmp

ln -s ../../src/libegalito.so
LD_LIBRARY_PATH=../../src EGALITO_DEBUG=/dev/null ../../src/loader \
	../binary/build/thread \
    >tmp/thread.out 2>&1
rm libegalito.so

if [ -z "$(diff hello.expected tmp/thread.out)" ]; then
    echo "test passed"
else
    echo "test failed!"
    exit 1
fi
