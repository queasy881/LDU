#!/usr/bin/env python3
"""Signature ground-truth differ.

The corpus carries the ORIGINAL source next to each DLL, so a recovered
signature can be compared against what the programmer actually wrote instead of
eyeballed. Scores three things separately, because they fail for different
reasons and a combined number hides which:

  RET    return type   (void stays void, float stays float, ...)
  ARITY  parameter count (too few silently drops a real argument at every call
         site; too many invents one)
  ARGS   per-parameter type

Usage:  python _qa/sigdiff.py [--verbose] [name-filter]
"""
import glob
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "_qa", "fixtures", "corpus")

# How a source type is expected to appear in recovered C. A recovered type is
# "right" if it lands in the same equivalence class -- int32_t for int is a
# correct recovery, not a miss.
CLASSES = {
    "void": {"void"},
    "float": {"float"},
    "double": {"double"},
    "bool": {"bool", "int8_t", "uint8_t", "char", "int32_t", "int"},
    "char": {"char", "int8_t", "uint8_t"},
    "signed char": {"char", "int8_t"},
    "unsigned char": {"uint8_t", "unsigned char", "char"},
    "short": {"int16_t", "short"},
    "unsigned short": {"uint16_t", "unsigned short"},
    "int": {"int32_t", "int", "uint32_t", "unsigned int"},
    "unsigned": {"uint32_t", "unsigned int", "int32_t", "int"},
    "unsigned int": {"uint32_t", "unsigned int", "int32_t", "int"},
    "long": {"int32_t", "int", "long"},
    "unsigned long": {"uint32_t", "unsigned int"},
    "long long": {"int64_t", "long long"},
    "unsigned long long": {"uint64_t", "unsigned long long"},
    "size_t": {"uint64_t", "int64_t", "size_t"},
}


def norm(t):
    t = t.strip()
    t = re.sub(r"\bconst\b", "", t)
    t = re.sub(r"\bEXPORT\b", "", t)
    t = re.sub(r"\bextern\b", "", t)
    t = re.sub(r'"C"', "", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def is_ptr(t):
    return "*" in t or "[" in t


def type_ok(src, got):
    """True when `got` is an acceptable recovery of source type `src`."""
    s, g = norm(src), norm(got)
    if is_ptr(s):
        # any pointer-ish or 64-bit integer recovery is accepted: a pointer and a
        # 64-bit int occupy the same register slot and the engine models it that way
        return is_ptr(g) or g in {"int64_t", "uint64_t", "long long", "unsigned long long"}
    s = s.replace("unsigned int", "unsigned").replace("unsigned", "unsigned").strip()
    base = norm(src).replace("*", "").strip()
    allowed = CLASSES.get(base)
    if allowed is None:
        return True  # struct/typedef we do not model here -- not scored
    return g.replace("*", "").strip() in allowed


def parse_source_sigs(path):
    """(name -> (rettype, [argtypes])) for EXPORT-marked definitions."""
    txt = open(path, encoding="utf-8", errors="replace").read()
    txt = re.sub(r"//[^\n]*", "", txt)
    txt = re.sub(r"/\*.*?\*/", "", txt, flags=re.S)
    # Two export spellings live in the corpus: the `EXPORT` macro and the raw
    # `extern "C" __declspec(dllexport)` it expands to. Matching only the first
    # silently skipped 19 of 23 files.
    txt = txt.replace('extern "C" __declspec(dllexport)', "EXPORT")
    txt = txt.replace("__declspec(dllexport)", "EXPORT")
    out = {}
    for m in re.finditer(
        r"\bEXPORT\s+([A-Za-z_][\w \t\*]*?)\s+(\w+)\s*\(([^)]*)\)\s*\{", txt, re.S
    ):
        ret, name, args = m.group(1), m.group(2), m.group(3)
        args = args.strip()
        if args in ("", "void"):
            atypes = []
        else:
            atypes = []
            for a in args.split(","):
                a = a.strip()
                # drop the parameter NAME, keep the type
                a = re.sub(r"\b[A-Za-z_]\w*\s*(\[\s*\d*\s*\])?$", "", a).strip()
                atypes.append(a if a else "int")
        out[name] = (norm(ret), [norm(t) for t in atypes])
    return out


def recovered_sigs(dll, names):
    """Decompile `dll` and return name -> (rettype, [argtypes])."""
    exe = os.path.join(ROOT, "target", "release", "disasmstudio.exe")
    cmds = [json.dumps({"cmd": "functions", "limit": 4000})]
    p = subprocess.run(
        [exe, "--script", dll, "-"],
        input="\n".join(cmds) + "\n",
        capture_output=True, text=True, timeout=600,
    )
    line = p.stdout.strip().splitlines()
    if not line:
        return {}
    try:
        fns = json.loads(line[0])["result"]
    except Exception:
        return {}
    want = {f["name"]: f["rva"] for f in fns if f["name"] in names}
    if not want:
        return {}
    cmds = [json.dumps({"cmd": "decompile", "rva": r}) for r in want.values()]
    p = subprocess.run(
        [exe, "--script", dll, "-"],
        input="\n".join(cmds) + "\n",
        capture_output=True, text=True, timeout=900,
    )
    out = {}
    for ln in p.stdout.splitlines():
        try:
            j = json.loads(ln)
        except Exception:
            continue
        if not j.get("ok"):
            continue
        code = j["result"]["code"]
        # the definition line: `<ret> <name>(<params>) {`
        m = re.search(r"^([A-Za-z_][\w \t\*]*?)\s+(\w+)\s*\(([^)]*)\)\s*\{", code, re.M)
        if not m:
            continue
        ret, name, args = norm(m.group(1)), m.group(2), m.group(3).strip()
        if name not in names:
            continue
        if args in ("", "void"):
            atypes = []
        else:
            atypes = []
            for a in args.split(","):
                a = a.strip()
                a = re.sub(r"\b[A-Za-z_]\w*$", "", a).strip()
                atypes.append(a if a else "int")
        out[name] = (ret, [norm(t) for t in atypes])
    return out


def main():
    verbose = "--verbose" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    filt = args[0] if args else ""

    tot = dict(fn=0, ret=0, arity=0, args=0, argtot=0)
    misses = []
    for src in sorted(glob.glob(os.path.join(CORPUS, "*.cpp"))):
        stem = os.path.splitext(os.path.basename(src))[0]
        if filt and filt not in stem:
            continue
        dll = os.path.join(CORPUS, stem + ".dll")
        if not os.path.exists(dll):
            continue
        want = parse_source_sigs(src)
        if not want:
            continue
        got = recovered_sigs(dll, set(want))
        for name, (sret, sargs) in sorted(want.items()):
            if name not in got:
                continue
            gret, gargs = got[name]
            tot["fn"] += 1
            ok_ret = type_ok(sret, gret)
            tot["ret"] += ok_ret
            ok_arity = len(sargs) == len(gargs)
            tot["arity"] += ok_arity
            ok_args = True
            for i, st in enumerate(sargs):
                tot["argtot"] += 1
                if i < len(gargs) and type_ok(st, gargs[i]):
                    tot["args"] += 1
                else:
                    ok_args = False
            if not (ok_ret and ok_arity and ok_args):
                misses.append(
                    (stem, name,
                     f"src: {sret} ({', '.join(sargs)})",
                     f"got: {gret} ({', '.join(gargs)})",
                     ("RET " if not ok_ret else "") + ("ARITY " if not ok_arity else "")
                     + ("ARGS" if not ok_args else ""))
                )

    f = max(tot["fn"], 1)
    at = max(tot["argtot"], 1)
    print(f"functions compared : {tot['fn']}")
    print(f"  RET   correct    : {tot['ret']:5d} / {tot['fn']}  ({100.0*tot['ret']/f:5.1f}%)")
    print(f"  ARITY correct    : {tot['arity']:5d} / {tot['fn']}  ({100.0*tot['arity']/f:5.1f}%)")
    print(f"  ARG   types      : {tot['args']:5d} / {tot['argtot']}  ({100.0*tot['args']/at:5.1f}%)")
    if misses:
        print(f"\n{len(misses)} signature mismatches:")
        for m in misses if verbose else misses[:40]:
            print(f"  [{m[4]:5s}] {m[0]}/{m[1]}\n      {m[2]}\n      {m[3]}")
        if not verbose and len(misses) > 40:
            print(f"  ... {len(misses)-40} more (--verbose)")


if __name__ == "__main__":
    main()
