#!/bin/bash
arch=$1

mkdir tmp 2>/dev/null

../../app/etshell >tmp/jumptable-libc.out <<EOF
parse ../binary/$arch/libc/libc.so.6
jumptables
EOF

cp ../binary/$arch/libc/table-list.txt tmp/jumptable-libc.1
perl -ne 'print if(s/jump table in //)' tmp/jumptable-libc.out \
    | sed 's/ at.* with / has /' | sort > tmp/jumptable-libc.2

./jumptable-diff.pl ../binary/$arch/libc/libc.so.6 \
    tmp/jumptable-libc.1 tmp/jumptable-libc.2 | tee tmp/jumptable-libc.diff

if [ -z "$(cat tmp/jumptable-libc.diff)" ]; then
    echo test passed
else
    echo test failed!
    exit 1
fi
