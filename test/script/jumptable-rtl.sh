#!/bin/bash
mkdir tmp 2>/dev/null

../../app/etshell >/dev/null >tmp/jumptable-rtl.out <<EOF
parse ../binary/build/jumptable
jumptables
EOF
gcc ../binary/target/jumptable/jumptable.c -fdump-final-insns=jumptable.c.finalrtl

./jumptables.pl jumptable.c.finalrtl | sed 's/.*in //' | sort > tmp/jumptable-rtl.1
perl -ne 'print if(s/jump table in //)' tmp/jumptable-rtl.out | sed 's/ at.* with / has /' | sort > tmp/jumptable-rtl.2

rm -f jumptable.c.finalrtl

if [ -z "$(diff tmp/jumptable-rtl.1 tmp/jumptable-rtl.2)" ]; then
    echo test passed
else
    echo test failed!
    exit 1
fi
