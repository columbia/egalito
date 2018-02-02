#!/bin/bash
mkdir -p tmp

# this takes a long time, so make a copy
cp -p ../../src/libegalito.so .
cp -p ../../src/loader .
rm -f tmp/coreutils.out
touch tmp/coreutils.out
for file in ../binary/target/coreutils/install/bin/*; do
  if [[ ${file: -2} == "-q" ]]; then
    continue
  fi
  echo $file >> tmp/coreutils.out
  EGALITO_DEBUG=/dev/null ./loader \
    $file --help \
      >tmp/`basename $file`.out 2>&1
  if [[ $? != 0 && $? != 1 ]]; then
    echo "test failed!"
    exit $?
  fi
done
rm libegalito.so
rm loader
echo "test passed"
