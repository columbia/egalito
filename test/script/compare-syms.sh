#!/bin/bash
mkdir -p tmp

if [ -z "$1" -o -z "$2" ]; then
    echo Usage: $0 exec1 exec2
    exit
fi

LD_LIBRARY_PATH=../../src ../../app/etshell >tmp/symbols.1 <<EOF
parse $1
functions3 module-(executable)
EOF
LD_LIBRARY_PATH=../../src ../../app/etshell >tmp/symbols.2 <<EOF
parse $2
functions3 module-(executable)
EOF

perl -ne '/0x([0-9a-f]+) 0x([0-9a-f]+)/ && print "0x$1 0x$2\n"' tmp/symbols.1 > tmp/symbols.1b
perl -ne '/0x([0-9a-f]+) 0x([0-9a-f]+)/ && print "0x$1 0x$2\n"' tmp/symbols.2 > tmp/symbols.2b

wc -l tmp/symbols.1b ; wc -l tmp/symbols.2b
diff tmp/symbols.{1,2}b
