#!/bin/bash

test=coreutils
debug=1

rm -f tmp/$test.1
rm -f tmp/$test.2
rm -f tmp/$test.3
rm -fr tmp/$test
touch tmp/$test.1
touch tmp/$test.2
touch tmp/$test.3
mkdir tmp/$test

bindir=../binary/aarch64-openSuSE/coreutils/coreutils

for file in $bindir/*; do
  count=`readelf -sW $file | grep " FUNC " | grep -v " UND " | awk '{print $2, $3}' | sort | uniq | wc -l`
  echo ${file##*/} $count >> tmp/$test.1
  if [ "$debug" -eq 1 ]
  then
    info=`readelf -sW $file | grep " FUNC " | grep -v " UND " | sort | uniq`
    printf '%s\n' "$info" > tmp/$test/${file##*/}.1
  fi
done

for file in $bindir/*; do
  echo "parsing $file"

  ../../app/etshell >tmp/$test.out << EOF
parse $file
functions3 module-(executable)
EOF
  count=`grep -i "0x[0-9a-f]\{8,\} 0x[0-9a-f]\{8,\}" tmp/$test.out | wc -l`
  echo ${file##*/} $count >> tmp/$test.2
  if [ "$debug" -eq 1 ]
  then
    info=`grep -i "0x[0-9a-f]\{8,\} 0x[0-9a-f]\{8,\}" tmp/$test.out`
    printf '%s\n' "$info" > tmp/$test/${file##*/}.2
  fi
  if [ "$count" -eq 0 ]
  then
    echo "something is wrong";
    exit 1
  fi
done

for file in $bindir-strip/*; do
  echo "parsing $file"

  ../../app/etshell >tmp/$test.out << EOF
parse $file
functions3 module-(executable)
EOF
  count=`grep -i "0x[0-9a-f]\{8,\} 0x[0-9a-f]\{8,\}" tmp/$test.out | wc -l`
  echo ${file##*/} $count >> tmp/$test.3
  if [ "$debug" -eq 1 ]
  then
    info=`grep -i "0x[0-9a-f]\{8,\} 0x[0-9a-f]\{8,\}" tmp/$test.out`
    printf '%s\n' "$info" > tmp/$test/${file##*/}.3
  fi
done

if [ ! -z "$(diff tmp/$test.{1,2})" ]; then
  #diff -y tmp/$test.{1,2}
  sdiff -bBWs tmp/$test.{1.2}
  echo "test failed (1 vs 2)"
fi

if [ -z "$(diff tmp/$test.{1,3})" ]; then
  echo "test passed"
else
  #diff -y tmp/$test.{1,3}
  sdiff -bBWs tmp/$test.{1,3}
  echo "test failed (1 vs 3)"
  exit 1
fi

