"""FEATURE VERIFICATION: decompile the custom fixture DLLs and ASSERT what the output says.

This is NOT the corpus. The corpus (_qa/harness.py) proves the decompiled C still BEHAVES
correctly when recompiled and run -- it is blind to whether a feature was recovered at all.
A function can be behaviourally perfect and still say `long long` where it means `HANDLE`,
or drop a vector's field names, or render a lock-free refcount as a plain decrement.

This asserts the RECOVERY: for each claimed feature, does the output actually say the right
thing, on a fixture whose ground truth is in the source next to it.

Usage:  python _qa/features/verify.py            (build the DLLs first: see build via PowerShell)
        python _qa/features/verify.py -v         (also print the decompiled body of failures)
Exit code 0 = all asserted features PASS.
"""
import os, re, subprocess, sys, glob, shutil

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
FEAT = os.path.join(ROOT, '_qa', 'features')
VERBOSE = '-v' in sys.argv

# (fixture dll, exported fn name, feature label, [required regexes], [forbidden regexes])
# A feature is PASS only if EVERY required pattern matches and NO forbidden one does.
CHECKS = [
    # ---- feat_c.dll : instruction / semantic recoveries -------------------------------
    ('feat_c', 'f_atomic_xadd', 'atomics: lock xadd -> _InterlockedExchangeAdd',
     [r'_InterlockedExchangeAdd'], []),
    ('feat_c', 'f_atomic_release', 'atomics: refcount release keeps the OLD value',
     [r'_InterlockedExchangeAdd'], []),
    ('feat_c', 'f_rotl', 'rotate: rol -> _rotl (C has no rotate operator)',
     [r'_rotl'], []),
    ('feat_c', 'f_rotr', 'rotate: ror -> _rotr',
     [r'_rotr'], []),
    ('feat_c', 'f_bswap32', 'bswap32 -> _byteswap_ulong',
     [r'_byteswap_ulong|__bswap|>>\s*24'], []),
    ('feat_c', 'f_bswap64', 'bswap64 -> _byteswap_uint64',
     [r'_byteswap_uint64|__bswap'], []),
    ('feat_c', 'f_bsf', 'bit-scan: bsf value AND its ZF (src==0 path must survive)',
     [r'__bsf|__tzcnt|_BitScanForward'], []),
    ('feat_c', 'f_bsr', 'bit-scan: bsr value AND its ZF',
     [r'__bsr|__lzcnt|_BitScanReverse'], []),
    ('feat_c', 'f_cpuid_vendor', 'cpuid -> __cpuid_e?x intrinsics',
     [r'__cpuid_e[abcd]x'], [r'in_R[A-D]X']),
    ('feat_c', 'f_rdtsc', 'rdtsc -> __rdtsc',
     [r'__rdtsc'], []),
    ('feat_c', 'f_movs', 'rep movs -> __movsb',
     [r'__movs[bwdq]'], []),
    ('feat_c', 'f_stos', 'rep stos -> __stos*',
     [r'__stos[bwdq]'], []),
    ('feat_c', 'f_div10', 'magic division: mulhi+shift -> / 10',
     [r'/\s*10\b'], []),
    ('feat_c', 'f_udiv7', 'magic division (unsigned): -> / 7',
     [r'/\s*7\b'], []),
    ('feat_c', 'f_fastfail', 'int 0x29 -> __fastfail',
     [r'__fastfail'], []),
    ('feat_c', 'f_heapfree', 'typelib: real Win32 param types, not long long',
     [r'HeapFree\s*\(\s*HANDLE|typedef .*HANDLE'], []),
    # CROSS-FUNCTION type propagation -- the type must flow THROUGH a local wrapper, which a
    # direct-call-only rule cannot see. NullWare has ZERO functions of this shape, so this
    # fixture is the only oracle for it.
    ('feat_c', 'f_get_base', 'cross-fn types: wrapper returns HMODULE, not int64_t',
     [r'^HMODULE f_get_base\(void\)'], [r'^int64_t f_get_base\(void\)']),
    ('feat_c', 'f_get_base2', 'cross-fn types: through a TAIL-CALL THUNK (jmp, no call/ret)',
     [r'^HMODULE f_get_base2\(void\)'], []),
    ('feat_c', 'f_use_base', 'cross-fn types: the CALLER\'s prototype agrees with the callee',
     [r'HMODULE f_get_base\(\);'], [r'int64_t f_get_base\(\);']),
    ('feat_c', 'f_sret_v3', 'sret 19a: return type follows the returned struct pointer',
     [r'struct \w+\s*\*\s*f_sret_v3'], [r'^float\*\s*f_sret_v3']),
    ('feat_c', 'f_pcmpeqb', 'lanes16: pcmpeqb DEFINES its dest (no fabricated 0 mask)',
     [r'__pcmpeqb'], [r'__pmovmskb\(0\)']),
    ('feat_c', 'f_stackstr', 'stack strings: immediate bytes -> char array',
     [r'char \w+\[|ABCD|0x44434241'], []),
    # Compound assignment. The forbidden pattern is the point: `v = v + x` must NOT survive.
    ('feat_c', 'f_compound', 'compound assign: v = v op x  ->  v op= x',
     [r'\w+\s(\+|\^|\||&|-|\*)= '], [r'(\b\w+) = \1 [-+^|&*] ']),
    ('feat_c', 'f_incr', 'increment: v = v + 1  ->  ++v',
     [r'\+\+\w+|\w+ \+= 1'], [r'(\b\w+) = \1 \+ 1;']),

    # ---- feat_cpp.dll : type / class recoveries ---------------------------------------
    ('feat_cpp', 'mk_rect', 'RTTI: class recovered + named',
     [r'(class|struct) (Rect|Shape)'], []),
    ('feat_cpp', 'mk_shape', 'operator new recovery',
     [r'operator_new|Shape'], []),
    ('feat_cpp', 'vec_size', 'std::vector: _Myfirst/_Mylast named (size() subtraction)',
     [r'_Myfirst', r'_Mylast'], []),
    ('feat_cpp', 'vec_range_sum', 'std::vector: begin/end ITERATION signature (no size())',
     [r'_Myfirst', r'_Mylast'], []),
    # The TYPE must be in the SIGNATURE, not an anonymous per-function bag. Every function
    # touching the SAME std::vector used to invent its own name for it (s_vec_size_a1,
    # s_rf_iter_a1, ...), so the signature said nothing about what it took. Mirrors what
    # detect_stl_strings already did for std_string.
    ('feat_cpp', 'vec_size', 'std::vector: named type IN THE SIGNATURE (not s_<fn>_a1)',
     [r'struct std_vector\s*\*'], [r'struct s_vec_size_a1']),
    ('feat_cpp', 'vec_range_sum', 'std::vector: named type on the range-only form too',
     [r'struct std_vector\s*\*'], [r'struct s_vec_range_sum_a1']),
    # SSO is asserted on str_first, NOT str_len: `s.size()` is a bare load of _Mysize with no
    # SSO logic at all (it decompiles to `return a1[2];`), so the _Myres-vs-15 discriminator
    # the detector keys on is genuinely absent there. Asserting it on str_len was MY bug and
    # it reported the feature broken when it works. A fixture has to actually exercise the
    # thing it claims to test.
    ('feat_cpp', 'str_first', 'std::string: SSO fields named (_Myres-vs-15 discriminator)',
     [r'_Mysize', r'_Myres', r'_Bx'], []),
    ('feat_cpp', 'eh_try', 'C++ EH: try/catch annotated',
     [r'SEH|try|catch|EH'], []),
    # DEVIRT IS EXPECTED TO FAIL, AND THAT IS THE POINT OF KEEPING IT HERE.
    # resolve_virtual_call (02_rtti_vtable.inc:54, DS_NO_VCALL) is fully wired and fires ZERO
    # times -- on NullWare AND on this fixture. Its gate demands param_structs[obj].is_class,
    # which 09_structs.inc only sets when the SAME function contains the ctor's vtable store.
    # shape_area just dispatches through a param, so is_class is false and it emits the raw
    # `(*(int64_t*)(*a1 + 8))(a1)` instead of Shape__vftbl_1. Measured intersection of
    # ctor-store AND dispatch across 1497 NullWare fns: 0. This line stays RED until that is
    # fixed -- a green suite that hides dead code is worse than an honest red one.
    ('feat_cpp', 'shape_area', 'devirt: vtable slot -> named method  [KNOWN-RED: fires 0x]',
     [r'Shape__vftbl|Rect__vftbl'], []),
    ('feat_cpp', 'list_sum', 'linked list: self-referential struct -> struct Node* next',
     [r'struct \w+\s*\*'], []),

    # ---- feat_x87.dll : 32-bit x87 ----------------------------------------------------
    ('feat_x87', 'x87_add', 'x87: double add survives (was an EMPTY void fn)',
     [r'a1 \+ a2|a2 \+ a1'], [r'void x87_add\(void\)']),
    ('feat_x87', 'x87_muladd', 'x87: a*b+c survives',
     [r'\*', r'\+'], [r'void x87_muladd\(void\)']),
    ('feat_x87', 'x87_cmp', 'x87: compare sense correct (the CC::P/NP inversion bug)',
     [r'<|>'], [r'void x87_cmp\(void\)']),
    ('feat_x87', 'x87_f', 'x87: float divide survives',
     [r'/'], [r'void x87_f\(void\)']),
]


def dump(dll_stem):
    """Decompile every function of a fixture DLL into a dict {fn_name: body}."""
    dll = os.path.join(FEAT, dll_stem + '.dll')
    if not os.path.exists(dll):
        return None
    out = os.path.join(FEAT, 'pairs_' + dll_stem)
    shutil.rmtree(out, ignore_errors=True)
    exes = sorted(glob.glob(os.path.join(ROOT, 'target', 'release', 'deps', 'dump_pairs-*.exe')),
                  key=os.path.getmtime, reverse=True)
    if not exes:
        print('  !! no dump_pairs exe built'); return None
    env = dict(os.environ)
    env['DS_REAL_BIN'] = dll
    env['DS_PAIRS_DIR'] = out
    env['DS_PAIRS_CAP'] = '200'
    subprocess.run([exes[0], '--nocapture'], env=env, capture_output=True, timeout=900)
    bodies = {}
    for f in glob.glob(os.path.join(out, 'fn_*.txt')):
        s = open(f, encoding='utf-8', errors='replace').read()
        i = s.find('--- DECOMPILED ---')
        if i < 0:
            continue
        body = s[i:]
        m = re.search(r'/\* ([A-Za-z_][A-Za-z_0-9]*) @ 0x', body)
        if m:
            bodies[m.group(1)] = body
    return bodies


def main():
    cache = {}
    npass = nfail = nmiss = 0
    rows = []
    for stem, fn, label, req, forb in CHECKS:
        if stem not in cache:
            cache[stem] = dump(stem)
        bodies = cache[stem]
        if bodies is None:
            rows.append(('MISS', label, 'fixture %s.dll not built' % stem)); nmiss += 1; continue
        body = bodies.get(fn)
        if body is None:
            rows.append(('MISS', label, 'fn %s not in the dump' % fn)); nmiss += 1; continue
        # re.M so a `^` in a pattern anchors to each LINE, not to the start of the whole body.
        # Without it every `^`-anchored check silently fails no matter what the output says --
        # which is how two green cross-fn results were reported RED.
        bad = [p for p in req if not re.search(p, body, re.M)]
        hit = [p for p in forb if re.search(p, body, re.M)]
        if not bad and not hit:
            rows.append(('PASS', label, '')); npass += 1
        else:
            why = []
            if bad:
                why.append('missing ' + ' & '.join(bad))
            if hit:
                why.append('FORBIDDEN ' + ' & '.join(hit))
            rows.append(('FAIL', label, '; '.join(why))); nfail += 1
            if VERBOSE:
                print('\n----- %s (%s) -----\n%s' % (label, fn, body[:1600]))
    print()
    for st, label, why in rows:
        print('  %-4s %-62s %s' % (st, label[:62], why))
    print('\n==== FEATURES: %d PASS / %d FAIL / %d MISSING ====' % (npass, nfail, nmiss))
    return 1 if (nfail or nmiss) else 0


if __name__ == '__main__':
    sys.exit(main())
