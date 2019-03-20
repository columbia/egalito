#!/bin/bash
mkdir -p tmp

DIR=../binary/target/codeform/dir

rm -f tmp/codeform.htm
ln -sf ../../src/libegalito.so
LD_LIBRARY_PATH=../../src ../../src/loader $DIR/codeform-s \
	-o tmp/codeform.htm $DIR/rules/c_1_html $DIR/codeform.c \
    >tmp/codeform-run.log 2>&1
rm libegalito.so

if [ -z "$(diff $DIR/../codeform-expected.html tmp/codeform.htm 2>&1)" ]; then
    echo "test passed"
else
    echo "test failed!"
    exit 1
fi
