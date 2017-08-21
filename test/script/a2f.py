#!/usr/bin/python

import subprocess
import re
import sys
import collections
import bisect

p = subprocess.Popen(["readelf", "-s", "bin-symbols.elf"],
        stdout=subprocess.PIPE)
#     0: 00000000004005e4    80 FUNC    GLOBAL DEFAULT    3 libc_exit_fini$new

sizes = {}
a = collections.OrderedDict()
for line in p.stdout.readlines():
    m = re.search('\d+:\s+(\w+)\s+(\w+)\s.+\s(\w+)\\$new', line)
    if m:
        sizes[int(m.group(1), 16)] = int(m.group(2))
        a[int(m.group(1), 16)] = m.group(3)

address = collections.OrderedDict(sorted(a.iteritems()))
#for k,v in address.items():
#    print(hex(k), v)
#    print(hex(k + sizes[k]))

for line in sys.stdin:
    m = re.search('(\w+)\s+([><])\s([_\w]+)', line)
    if m:
        if m.group(2) == '>': print '-->',
        else: print '<--',
        a = int(m.group(3), 16)
        #print format(a, 'X'),
        ind = bisect.bisect_right(address.keys(), a)
        if ind:
            #print ind,
            print address.values()[ind - 1], format(a, 'x')
