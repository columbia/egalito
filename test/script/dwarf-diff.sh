#!/bin/bash
mkdir tmp 2>/dev/null

for program in ../binary/build/hello ../binary/target/codeform/dir/codeform; do
    LD_LIBRARY_PATH=../../src EGALITO_DEBUG=/dev/null:dwarf=20 ../../app/etshell >tmp/dwarf-diff.egalito <<EOF
parse $program
dwarf
EOF
    objdump -g $program | sed '1,3 d' | grep -v 'Augmentation data:' \
        | perl -pe '/Contents of the \.debug.* section:/ && exit' \
        >tmp/dwarf-diff.objdump
    cat tmp/dwarf-diff.egalito | sed '1,3 d' | head -n -1 > tmp/dwarf-diff.egalito.2
    diff tmp/dwarf-diff.objdump tmp/dwarf-diff.egalito.2

    if [ "$?" != 0 ]; then
        echo test failed, $program
        exit 1
    fi
done

echo test passed
