#!/usr/bin/env python3
# Count decompiled temp DECLARATIONS (vN / tN locals) across _qa/decomp/*.c.
# A declaration is a line beginning with a C type keyword and declaring a vN/tN
# identifier — distinct from a bare assignment (`v2 = a3;`) which has no type.
import glob, re, os
DECOMP = os.path.join(os.path.dirname(__file__), "decomp")
TYPE = r'(?:unsigned\s+|signed\s+)?(?:long\s+long|long|int|char|short|float|double|void|bool|__int64|struct\s+\w+)\s*\**\s*'
DECL = re.compile(r'^\s+' + TYPE + r'([vt][0-9]+)\b\s*(?:=|;|\[)')
total = 0
per = {}
for f in sorted(glob.glob(os.path.join(DECOMP, "*.c"))):
    n = 0
    for line in open(f, encoding="utf-8", errors="replace"):
        if DECL.match(line):
            n += 1
    per[os.path.basename(f)] = n
    total += n
print("tN/vN decls total:", total)
