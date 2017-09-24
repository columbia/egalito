#!/bin/bash
mkdir -p tmp

DIR=../binary/target/codeform/dir

LD_LIBRARY_PATH=../../src ../../app/etshell >tmp/codeform.sym <<EOF
parse $DIR/codeform
functions3 module-(executable)
EOF
LD_LIBRARY_PATH=../../src ../../app/etshell >tmp/codeform-s.sym <<EOF
parse $DIR/codeform-s
functions3 module-(executable)
EOF

perl -ne '/0x([0-9a-f]+) 0x([0-9a-f]+)/ && print "0x$1 0x$2\n"' tmp/codeform.sym > tmp/codeform-sym.1
perl -ne '/0x([0-9a-f]+) 0x([0-9a-f]+)/ && print "0x$1 0x$2\n"' tmp/codeform-s.sym > tmp/codeform-sym.2

diff -y tmp/codeform-sym.{1,2}
