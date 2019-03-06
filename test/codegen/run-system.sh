#!/bin/bash
mkdir -p tmp

mode=$1
prog=$2
if [ -z "$mode" -o -z "$prog" ]; then
    echo "Usage: $0 mode test-program" 1>&2
    echo "test failed!"
    exit 1
fi
base=tmp/$(basename $prog)

rm -f $base{,.log,.out}
../../app/etelf $mode $prog $base > $base.log 2>&1
$base --help > $base.out 2>&1

if [ "$?" -eq 0 -a "$(cat $base.out | wc -l)" -gt 0 ]; then
    echo "test passed"
else
    echo "test failed!"
    exit 1
fi
