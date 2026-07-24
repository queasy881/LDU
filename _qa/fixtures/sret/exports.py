"""Dump a PE's export names + how many are MSVC-mangled. Read-only recon."""
import sys, struct

def dump(path):
    d = open(path, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    opt = pe + 24
    magic = struct.unpack_from('<H', d, opt)[0]
    dd = opt + (112 if magic == 0x20b else 96)
    era, ers = struct.unpack_from('<II', d, dd)
    so = opt + struct.unpack_from('<H', d, pe + 20)[0]
    secs = []
    for i in range(nsec):
        o = so + 40 * i
        vs = struct.unpack_from('<I', d, o + 8)[0]
        va = struct.unpack_from('<I', d, o + 12)[0]
        pr = struct.unpack_from('<I', d, o + 20)[0]
        secs.append((va, vs, pr))

    def r2o(r):
        for va, vs, pr in secs:
            if va <= r < va + max(vs, 1):
                return pr + (r - va)
        return None

    if not era:
        print("  %s: NO EXPORT TABLE" % path)
        return
    eo = r2o(era)
    nn = struct.unpack_from('<I', d, eo + 24)[0]
    anp = struct.unpack_from('<I', d, eo + 32)[0]
    po = r2o(anp)
    names = []
    for i in range(nn):
        nr = struct.unpack_from('<I', d, po + 4 * i)[0]
        o = r2o(nr)
        e = d.index(b'\0', o)
        names.append(d[o:e].decode('ascii', 'replace'))
    mang = [n for n in names if n.startswith('?')]
    print("  %s: %d exports, %d MANGLED" % (path, len(names), len(mang)))
    for n in (mang or names)[:8]:
        print("     " + n)

for p in sys.argv[1:]:
    try:
        dump(p)
    except Exception as e:
        print("  %s: ERR %s" % (p, e))
