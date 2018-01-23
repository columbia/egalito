#!/bin/bash
mkdir -p tmp

# this takes a long time, so make a copy
cp -p ../../src/libegalito.so .
rm -f tmp/coreutils.out
touch tmp/coreutils.out
for file in ../binary/target/coreutils/install/bin/*; do
  echo $file >> tmp/coreutils.out
  LD_LIBRARY_PATH=../../src EGALITO_DEBUG=/dev/null ../../src/loader \
    $file --help \
      >tmp/`basename $file`.out 2>&1
  if [[ $? != 0 && $? != 1 ]]; then
    echo "test failed!"
    exit $?
  fi
done
rm libegalito.so
echo "test passed"
