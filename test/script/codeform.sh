#!/bin/bash
mkdir -p tmp

DIR=../binary/target/codeform/dir

ln -s ../../src/libegalito.so
LD_LIBRARY_PATH=../../src ../../src/loader $DIR/codeform \
	-o tmp/codeform.htm $DIR/rules/c_1_html $DIR/codeform.c \
    >tmp/codeform-run.log 2>&1
rm libegalito.so

if [ -z "$(diff $DIR/../codeform-expected.html tmp/codeform.htm)" ]; then
    echo "test passed, no diff in codeform output"
else
    echo "test failed!"
    exit 1
fi
