#!/bin/bash
mkdir -p tmp

ln -sf ../../src/libegalito.so
LD_LIBRARY_PATH=../../src EGALITO_DEBUG=/dev/null ../../src/loader \
	../binary/build/fork \
    >tmp/fork.out 2>&1
rm libegalito.so

grep -q "\[parent\] Hello, World!" tmp/fork.out
if [ "$?" != 0 ]; then
  echo test failed!
  exit 1
fi

grep -q "\[child\] Hello, World!" tmp/fork.out
if [ "$?" != 0 ]; then
  echo test failed!
  exit 1
fi
echo test passed
