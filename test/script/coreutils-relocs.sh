#!/bin/bash
mkdir -p tmp

cp -p ../../src/libegalito.so .
cp -p ../../src/loader .
rm -f tmp/coreutils.out
touch tmp/coreutils.out
for file in ../binary/target/coreutils/install/bin/*; do
  if [[ ${file: -2} == "-q" ]]; then
    continue
  fi
  #echo checking $file
  echo $file >> tmp/coreutils-relocs.out
  ./relocheck.sh $file
  if [[ $? == 1 ]]; then
    echo "test failed!"
    exit 1
  fi
  #read -p "continue?" yn
  #case $yn in
    #n) exit;;
    #*) ;;
  #esac
done
rm libegalito.so
rm loader
echo "test passed"
