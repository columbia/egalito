#!/bin/bash

find ../binary/x86_64-debian/libc -name '*.c.*' | grep -v 'elf/dl-' \
    | xargs ./jumptables.pl \
    | ./filterinside.pl ../binary/x86_64-debian/libc/libc.so.6 \
    | grep -Ev '\[_dl_start\]' \
    | sed 's/.*in //' | sort > ../binary/x86_64-debian/libc/table-list.txt
