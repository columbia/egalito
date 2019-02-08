#!/bin/bash
mkdir -p tmp

mode=$1
prog=$2
shift
shift
if [ -z "$mode" -o -z "$prog" ]; then
    echo "Usage: $0 mode test-program" 1>&2
    echo "test failed!"
    exit 1
fi

rm -f tmp/$prog{,.log,.out,.expected}
../binary/build/$prog $@ > tmp/$prog.expected 2>&1
../../app/etelf $mode ../binary/build/$prog tmp/$prog > tmp/$prog.log 2>&1
./tmp/$prog $@ > tmp/$prog.out 2>&1

if [ -z "$(diff tmp/$prog.expected tmp/$prog.out)" ]; then
    echo "test passed"
else
    echo "test failed!"
    exit 1
fi
