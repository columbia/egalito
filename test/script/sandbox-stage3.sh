#!/bin/bash
mkdir -p tmp

rm -f tmp/sandbox-stage3 
EGALITO_DEBUG=/dev/null ../../app/etshell > tmp/sandbox-stage3.out <<EOF
parse2 ../../src/ex/sandbox-stage3
add-library ../../app/libsandbox.so
endbradd
endbrenforce
sandboxenforce
collapseplt
promotejumps
generate-static tmp/sandbox-stage3
EOF

./tmp/sandbox-stage3
if [ "$?" -eq "10" ]; then
    echo "test passed"
else
    echo "test failed!"
    exit 1
fi
