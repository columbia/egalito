#!/bin/bash
mkdir -p tmp

ln -sf ../../src/libegalito.so
LD_LIBRARY_PATH=../../src EGALITO_DEBUG=/dev/null ../../src/loader \
	../binary/build/islower 2>&1 \
    | tail -n 2 >tmp/islower.out
rm libegalito.so

if [ -z "$(diff islower.expected tmp/islower.out)" ]; then
    echo "test passed"
else
    echo "test failed! this is usually because callInitFunctions isn't running"
    exit 1
fi
