#!/usr/bin/env python3
# Behavioral-equivalence oracle for the DisasmStudio decompiler.
#
# For each corpus DLL:
#   1. compile _qa/decomp/<dll>.c  -> dec_<dll>.dll  (the decompiled functions)
#   2. generate a driver that loads the ORIGINAL <dll>.dll and the decompiled
#      dll, and for every exported function calls both with identical random +
#      edge inputs (typed per signature), comparing return values and any
#      out-parameters / mutated buffers.
#   3. compile + run the driver; report per-function PASS/FAIL.
#
# "Perfect" = every function PASSES on every input.

import os, re, sys, glob, shutil, subprocess, collections, concurrent.futures

from qapaths import QA, CORPUS, DECOMP, WORK, ensure_out, find_vcvars

ensure_out(WORK, DECOMP)
VCVARS = find_vcvars()
if not VCVARS:
    sys.exit("vcvars64.bat not found; set VCVARS=<path to vcvars64.bat>")
# auto-discover every corpus source so new test files are picked up automatically
DLLS = sorted(os.path.splitext(os.path.basename(f))[0] for f in glob.glob(os.path.join(CORPUS, "*.cpp")))
N = int(os.environ.get("HARNESS_N", "50000"))  # tests per function — exhaustive

# Matches an exported definition. Accepts both the literal attribute and the
# `#define EXPORT extern "C" __declspec(dllexport)` macro some corpus files use,
# and a `*`-adjacent pointer return (`char *foo`) where no space separates the
# star from the name.
SIG = re.compile(
    r'(?:EXPORT\b|extern\s+"C"\s+__declspec\(dllexport\))\s+'
    r'([A-Za-z_][\w\s\*]*?)\s*\b([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{', re.S)

def parse_params(p):
    p = p.strip()
    if p in ("", "void"): return []
    return [x.strip() for x in p.split(",")]

def param_kind(p, structs):
    # returns (kind, base) ; kind in
    #   scalar/i64/iarr_c/iarr_m/str_c/str_m/struct_c/struct_m/struct_val
    isptr = "*" in p
    isconst = "const" in p
    toks = p.replace("const", "").replace("*", "").strip().split()
    t = toks[0] if toks else "int"
    # the TYPE tokens are everything except the trailing parameter name; checking
    # the name too would misclassify e.g. `const int *search` (name contains
    # "char"... no, but `*charCount`) as a char string.
    type_toks = toks[:-1] if len(toks) >= 2 else toks
    if t in structs:
        if isptr:
            return ("struct_c" if isconst else "struct_m", t)
        return ("struct_val", t)
    if not isptr:
        return ("i64" if ("int64" in p or "long" in p) else "scalar", t)
    if "char" in type_toks:
        return ("str_c" if isconst else "str_m", "char")
    # int* / int64* / other-pointer array
    return ("iarr_c" if isconst else "iarr_m", t)

def ret_kind(r, structs=()):
    r = r.strip()
    r = re.sub(r'\b(EXPORT|extern|__declspec\(dllexport\)|static|const)\b', '', r).strip()
    if r == "void": return "void"
    if "*" in r: return "ptr"
    if "double" in r or "float" in r: return "fp"
    toks = r.split()
    base = toks[-1] if toks else r
    if base in structs: return "struct"
    if "int64" in r or "long" in r: return "i64"
    return "int"

def parse_sigs():
    # PER-FILE signatures: {dll: {name: (ret, params)}}. A global name->sig map
    # let a function in a later file (e.g. a manhattan(const Point*,const Point*))
    # clobber a same-named function in another file (geometry's manhattan(int,...)),
    # so the driver called it with the wrong ABI -> false failures.
    sigs = {}
    for f in DLLS:
        src = open(os.path.join(CORPUS, f + ".cpp"), encoding="utf-8", errors="replace").read()
        d = {}
        for m in SIG.finditer(src):
            ret, name, params = m.group(1).strip(), m.group(2), m.group(3)
            d[name] = (ret, parse_params(params))
        sigs[f] = d
    return sigs

_ENV_READY = [False]
def setup_msvc_env():
    # Capture the MSVC env ONCE (running vcvars per cl call was the bottleneck).
    # Use a temp .bat that dumps `set` to a file — robust against inline quoting
    # and the system's OEM codepage (paths are ASCII, so errors='replace' is safe).
    if _ENV_READY[0]:
        return
    os.makedirs(WORK, exist_ok=True)
    bat = os.path.join(WORK, "_env.bat")
    envf = os.path.join(WORK, "_env.txt")
    open(bat, "w").write('@echo off\r\ncall "%s"\r\nset > "%s"\r\n' % (VCVARS, envf))
    subprocess.run(["cmd", "/c", bat], capture_output=True)
    for line in open(envf, encoding="utf-8", errors="replace").read().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            os.environ[k] = v
    _ENV_READY[0] = True
    if not shutil.which("cl"):
        raise RuntimeError("cl not on PATH after vcvars; check %s" % VCVARS)

def run_bat(lines):
    setup_msvc_env()
    bat = os.path.join(WORK, "_run.bat")
    open(bat, "w").write('@echo off\r\n' + "\r\n".join(lines) + "\r\n")
    return subprocess.run(["cmd", "/c", bat], capture_output=True, text=True)

# ---- driver generation ----------------------------------------------------
# Per-corpus-file type info: the source preamble (everything before the first
# exported function — all the struct/typedef defs) and {struct_name: has_pointer}.
# Injected verbatim so the driver knows every struct type the original uses.
_FILE_TYPES = {}
def file_types(dll):
    if dll in _FILE_TYPES:
        return _FILE_TYPES[dll]
    src = open(os.path.join(CORPUS, dll + ".cpp"), encoding="utf-8", errors="replace").read()
    out, names, seen = [], {}, set()
    for m in re.finditer(r'#include\s+[<"][^>"]+[>"]', src):
        if m.group(0) not in seen:
            seen.add(m.group(0)); out.append(m.group(0))
    # object-like #defines (e.g. HEAP_CAP, RING_CAP) — structs use them for array
    # sizes, so they must be injected before the type definitions below.
    for m in re.finditer(r'#define\s+\w+[^\n\\]*', src):
        if m.group(0) not in seen:
            seen.add(m.group(0)); out.append(m.group(0))
    # Every type definition anywhere in the file, IN SOURCE ORDER (some corpus
    # files declare structs midway, after earlier exported functions). Order
    # preserves inter-type dependencies. Match struct blocks and simple typedefs.
    for m in re.finditer(r'typedef\s+struct\s+\w*\s*\{.*?\}\s*\w+\s*;'
                         r'|struct\s+\w+\s*\{.*?\}\s*;'
                         r'|typedef\s+[^;{}]+\s+\w+\s*;', src, re.S):
        text = m.group(0)
        if text in seen:
            continue
        seen.add(text); out.append(text)
        ms = re.search(r'\}\s*(\w+)\s*;', text)
        if ms and 'struct' in text:
            names[ms.group(1)] = ("*" in text)
        ms2 = re.match(r'struct\s+(\w+)\s*\{', text)
        if ms2:
            names.setdefault(ms2.group(1), ("*" in text))
    _FILE_TYPES[dll] = ("\n".join(out), names)
    return _FILE_TYPES[dll]

def c_type_of(p):
    # canonical C type for the ORIGINAL signature parameter (for the fn-ptr typedef)
    return re.sub(r'\b[A-Za-z_]\w*\s*$', '', p).strip() or "int"

def recursive_funcs(dll):
    """Names whose DECOMPILED body calls themselves — they need a tiny input
    bound or they (and the original) hang on exponential/factorial recursion."""
    path = os.path.join(DECOMP, dll + ".c")
    if not os.path.exists(path):
        return set()
    txt = open(path, encoding="utf-8", errors="replace").read()
    rec = set()
    for ch in txt.split("/* ==== ")[1:]:
        m = re.match(r'(\w+) @', ch)
        if not m:
            continue
        name = m.group(1)
        body = ch.split("/* ==== ")[0]
        if len(re.findall(r'\b' + re.escape(name) + r'\s*\(', body)) >= 2:
            rec.add(name)
    return rec

def gen_driver(dll, sigs, manifest_names):
    preamble, structs = file_types(dll)
    recursive = recursive_funcs(dll)
    L = []
    L.append('#include <windows.h>')
    L.append('#include <stdio.h>')
    L.append('#include <stdint.h>')
    L.append('#include <string.h>')
    # inject the corpus file's own struct/typedef definitions so the driver knows
    # every type the original signatures use (compiled as C++ for struct support).
    L.append(preamble)
    L.append('static unsigned long _s=2463534242UL;')
    L.append('static int R(){_s^=_s<<13;_s^=_s>>17;_s^=_s<<5;return (int)_s;}')
    # Scalar params double as loop bounds and array indices, so they are BOUNDED
    # to [-2000,2000]: a correct counting loop on INT_MAX would run ~2e9 iterations
    # (false "hang"), and a raw index of INT_MAX would read out of bounds (crash).
    # Array buffers are padded and passed at their middle, so any index in range is
    # in-bounds. Edge values still cover the small boundaries where bugs hide.
    L.append('static int Redge(int i){static const int e[]={0,1,-1,2,-2,3,-3,4,7,-7,8,15,16,31,32,63,64,100,-100,127,128,-128,255,256,-256,511,512,1000,-1000,1023,1024,2000,-2000,17,-17,42,99,-99,1999,-1999,9,-9,13,200};int k=(int)(sizeof(e)/sizeof(e[0])); if(i<k)return e[i]; if((i&3)==0){return e[((unsigned)R())%(unsigned)k];} return (int)((unsigned)R()%4001u)-2000;}')
    # Small bound for scalars in functions that ALSO take an array: those scalars
    # are matrix dimensions / indices, and a function iterating rows*cols must stay
    # within the (middle-passed, 4096-forward) buffer. |x|<=48 => products <=2304.
    L.append('static int RedgeS(int i){static const int e[]={0,1,-1,2,3,4,5,7,8,15,16,31,32,48,-2,-3,-5,-8,-16,-32,6,10,12,20,24,9,11,13,17,40,-40,-48};int k=(int)(sizeof(e)/sizeof(e[0])); if(i<k)return e[i]; return (int)((unsigned)R()%97u)-48;}')
    # Tiny bound for RECURSIVE functions: an O(n!) cofactor determinant or an
    # exponential fib hangs the ORIGINAL too at n=2000 (a false "hang"), so a
    # recursive function's scalar inputs are clamped to [-2,8]. fib(8)=21,
    # det of an 8x8 = 40320 calls — both fast and still exercise the recursion.
    L.append('static int RedgeTiny(int i){static const int e[]={0,1,2,3,4,5,6,7,8,-1,-2};int k=11; if(i<k)return e[i]; return (int)((unsigned)R()%9u);}')
    L.append('static HMODULE O,D; static int total_fail=0;')
    L.append('int main(){')
    L.append('  O=LoadLibraryA("%s.dll"); D=LoadLibraryA("dec_%s.dll");' % (dll, dll))
    L.append('  if(!O||!D){printf("LOADFAIL O=%p D=%p\\n",(void*)O,(void*)D);return 2;}')
    tested = 0
    for name in manifest_names:
        if name not in sigs: continue
        ret, params = sigs[name]
        rk = ret_kind(ret, structs)
        kinds = [param_kind(p, structs) for p in params]
        ctypes = [c_type_of(p) for p in params]
        # only handle shapes we can drive; else skip (reported)
        L.append('  { /* %s */' % name)
        L.append('    typedef %s (*FP)(%s);' % (ret if rk!="ptr" else "void*", ",".join(ctypes) if ctypes else "void"))
        L.append('    FP fo=(FP)GetProcAddress(O,"%s"); FP fd=(FP)GetProcAddress(D,"%s");' % (name, name))
        L.append('    if(!fo||!fd){printf("MISS %s\\n");}else{int fails=0;')
        # flush a marker BEFORE the loop so a hang (infinite loop in decompiled
        # code) is attributable to this function from the partial stdout.
        L.append('    printf("RUN %s\\n"); fflush(stdout);' % name)
        L.append('    for(int t=0;t<%d;t++){' % N)
        # build args
        argo=[]; argd=[]; setup=[]; post=[]; firstp=None
        # When the function also takes an array, its scalars are dimensions/indices;
        # bound them small so a rows*cols iteration stays inside the buffer.
        has_arr = any(kk in ("iarr_c","iarr_m","struct_c","struct_m","str_c","str_m") for kk,_ in kinds)
        RE = "RedgeTiny" if name in recursive else ("RedgeS" if has_arr else "Redge")
        i=0
        while i < len(kinds):
            k,base = kinds[i]
            if k in ("scalar","i64"):
                # both bounded (an i64 loop bound would hang just like a 32-bit one)
                v = "%s(t)" % RE if k=="scalar" else "((long long)%s(t)*10LL+%s(t+1))" % (RE, RE)
                setup.append('      %s A%d=(%s)%s;' % (ctypes[i], i, ctypes[i], v))
                argo.append("A%d"%i); argd.append("A%d"%i); i+=1
            elif k in ("iarr_c","iarr_m"):
                # Padded buffer passed at its MIDDLE so any index in [-2000,2000]
                # (incl. explicit index params like swap_ints(a,i,j)) stays in
                # bounds. Cast to the original element type (C++ won't implicitly
                # convert int* -> uint32_t*). Compare the whole buffer for writes.
                ct = ctypes[i]
                setup.append('      static int bo%d[8192],bd%d[8192]; for(int q=0;q<8192;q++){int rv=R(); bo%d[q]=rv; bd%d[q]=rv;}' % (i,i,i,i))
                setup.append('      %s boP%d=(%s)(bo%d+4096); %s bdP%d=(%s)(bd%d+4096);' % (ct,i,ct,i,ct,i,ct,i))
                if k == "iarr_c":
                    # CONST array: same buffer to both (read-only; separate buffers
                    # diverge only falsely on a stored pointer / out-of-range index).
                    argo.append("boP%d"%i); argd.append("boP%d"%i)
                    if firstp is None: firstp=("boP%d"%i,"boP%d"%i)
                else:
                    argo.append("boP%d"%i); argd.append("bdP%d"%i)
                    if firstp is None: firstp=("boP%d"%i,"bdP%d"%i)
                    post.append('        if(memcmp(bo%d,bd%d,sizeof(bo%d))!=0) ok=0;' % (i,i,i))
                # consume following int as length (bounded small so loops are fast)
                if i+1<len(kinds) and kinds[i+1][0]=="scalar":
                    setup.append('      int LN%d=(t%%17);'%i); argo.append("LN%d"%i); argd.append("LN%d"%i); i+=2
                else:
                    i+=1
            elif k in ("str_c","str_m"):
                # Fill ALL 40 bytes identically (not just up to the null), else the
                # memcmp below compares uninitialized stack tails that differ between
                # the two buffers -> false FAIL. Null-terminate at a random length.
                # 256-byte buffer (byte-array funcs process up to ~48 bytes given
                # the small-bound on the length scalar); null-terminated for true
                # string functions. Filled fully+identically so the memcmp is valid.
                setup.append('      char so%d[256],sd%d[256]; for(int q=0;q<256;q++){int c=33+(R()&63); so%d[q]=(char)c; sd%d[q]=(char)c;} int sl%d=(t%%20); so%d[sl%d]=0; sd%d[sl%d]=0;' % (i,i,i,i,i,i,i,i,i))
                # cast to the exact param type so C++ accepts unsigned/signed char*
                ct = ctypes[i]
                if k == "str_c":
                    # CONST string: the function only READS it, so pass the SAME
                    # buffer to both. Two separate buffers can only diverge FALSELY
                    # for read-only input — on a stored input pointer (state_init's
                    # st->buf) or an out-of-range scan past the logical end into the
                    # printable tail / OOB (skip_to_ws / next_token_len with from>len).
                    argo.append("(%s)so%d"%(ct,i)); argd.append("(%s)so%d"%(ct,i))
                    if firstp is None: firstp=("so%d"%i,"so%d"%i)
                else:
                    argo.append("(%s)so%d"%(ct,i)); argd.append("(%s)sd%d"%(ct,i))
                    if firstp is None: firstp=("so%d"%i,"sd%d"%i)
                    post.append('        if(memcmp(so%d,sd%d,sizeof(so%d))!=0) ok=0;'%(i,i,i))
                i+=1
            elif k in ("struct_c","struct_m"):
                hasptr = structs.get(base, False)
                # a struct pointer followed by an int is (almost always) an array +
                # length; cap the count small and allocate generously so even a
                # single-struct out-param mistaken for an array stays in-bounds.
                is_array = (i+1 < len(kinds) and kinds[i+1][0] == "scalar")
                # CONST struct pointer: the function only READS it, so pass the SAME
                # buffer to both. Random struct fill makes internal indices (head/
                # next/links) out of range, so two separate buffers read different
                # OUT-OF-BOUNDS garbage past them -> false divergence (list_max/min).
                is_const = (k == "struct_c")
                if is_array:
                    # 16 structs CENTERED in a zeroed buffer. A single large struct
                    # mistaken for an array (List/Heap + index/value, where the int
                    # is NOT a count) reads out of bounds from invalid internal
                    # indices; centering makes those reads deterministic zeros in
                    # both copies instead of divergent adjacent memory.
                    setup.append('      static char _ao%d[32768],_ad%d[32768]; memset(_ao%d,0,32768); memset(_ad%d,0,32768); %s* ao%d=(%s*)(_ao%d+8192); %s* ad%d=(%s*)(_ad%d+8192);' % (i,i,i,i,base,i,base,i,base,i,base,i))
                    if not hasptr:
                        setup.append('      {int*po=(int*)ao%d;int*pd=(int*)ad%d;int nw=16*(int)(sizeof(%s)/4);for(int q=0;q<nw;q++){int b=(int)((unsigned)R()%%2000)-1000;po[q]=b;pd[q]=b;}}' % (i,i,base))
                    setup.append('      int LN%d=(t%%9);' % i)
                    argo.append("ao%d"%i); argo.append("LN%d"%i)
                    if is_const:
                        argd.append("ao%d"%i); argd.append("LN%d"%i)
                    else:
                        argd.append("ad%d"%i); argd.append("LN%d"%i)
                        post.append('        if(memcmp(ao%d,ad%d,16*sizeof(%s))!=0) ok=0;'%(i,i,base))
                    i+=2
                else:
                    # The struct sits in the MIDDLE of a zeroed buffer so that
                    # out-of-bounds accesses from random/invalid internal indices
                    # (heap/list links are filled [-1000,1000] -> nodes[idx]*8 is
                    # +-8000 bytes) read deterministic ZEROS in both copies instead
                    # of divergent adjacent stack memory. Pointers xo/xd alias into
                    # the buffers; the struct itself (and only it) is compared.
                    setup.append('      static char _so%d[24576],_sd%d[24576]; memset(_so%d,0,24576); memset(_sd%d,0,24576); %s* xo%d=(%s*)(_so%d+8192); %s* xd%d=(%s*)(_sd%d+8192);' % (i,i,i,i,base,i,base,i,base,i,base,i))
                    if not hasptr:
                        clamp = '{int*pc=(int*)xo%d;int*qc=(int*)xd%d;int nl=(int)(sizeof(%s)/4);pc[nl-1]=qc[nl-1]=(R()&63);}'%(i,i,base) if base=="Stack" else ''
                        setup.append('      {int*po=(int*)xo%d;int*pd=(int*)xd%d;int nf=(int)(sizeof(%s)/4);for(int q=0;q<nf;q++){int b=(int)((unsigned)R()%%2000)-1000;po[q]=b;pd[q]=b;}} %s' % (i,i,base,clamp))
                    argo.append("xo%d"%i)
                    if is_const:
                        argd.append("xo%d"%i)
                    else:
                        argd.append("xd%d"%i)
                        post.append('        if(memcmp(xo%d,xd%d,sizeof(%s))!=0) ok=0;'%(i,i,base))
                    i+=1
            elif k == "struct_val":
                # struct passed BY VALUE (e.g. Point a). Fill identically; no
                # out-param compare (the callee gets its own copy).
                hasptr = structs.get(base, False)
                if hasptr:
                    setup.append('      %s vo%d,vd%d; memset(&vo%d,0,sizeof(vo%d)); memset(&vd%d,0,sizeof(vd%d));' % (base,i,i,i,i,i,i))
                else:
                    setup.append('      %s vo%d,vd%d; {int*po=(int*)&vo%d;int*pd=(int*)&vd%d;int nf=(int)(sizeof(%s)/4);for(int q=0;q<nf;q++){int b=(int)((unsigned)R()%%2000)-1000;po[q]=b;pd[q]=b;}}' % (base,i,i,i,i,base))
                argo.append("vo%d"%i); argd.append("vd%d"%i)
                i+=1
            else:
                i+=1
        L += setup
        L.append('      int ok=1;')
        if rk=="void":
            L.append('      fo(%s); fd(%s);' % (",".join(argo), ",".join(argd)))
        elif rk=="fp":
            # Compare fp returns with a relative tolerance (benign reassociation in
            # the decompiled form must not false-fail) and treat NaN==NaN as equal.
            L.append('      double ro=(double)fo(%s), rd=(double)fd(%s);' % (",".join(argo), ",".join(argd)))
            L.append('      if(ro!=rd){int no=(ro!=ro),nd=(rd!=rd); if(no||nd){ if(no!=nd) ok=0; } else { double d=ro-rd; if(d<0)d=-d; double m=ro<0?-ro:ro; double mn=rd<0?-rd:rd; if(mn>m)m=mn; if(d>1e-6*m+1e-12) ok=0; }}')
        elif rk=="struct":
            # Struct-by-value return (Win64: <=16B all-float in xmm0:xmm1, else sret).
            # Compare the returned aggregates bit-exact.
            base = ret.strip()
            base = re.sub(r'\b(EXPORT|extern|__declspec\(dllexport\)|static|const)\b', '', base).strip()
            L.append('      %s ro=fo(%s), rd=fd(%s); if(memcmp(&ro,&rd,sizeof(%s))!=0) ok=0;' % (base, ",".join(argo), ",".join(argd), base))
        elif rk=="i64":
            L.append('      long long ro=(long long)fo(%s), rd=(long long)fd(%s); if(ro!=rd) ok=0;' % (",".join(argo), ",".join(argd)))
        elif rk=="ptr":
            if firstp:
                # Compare returned pointers by OFFSET into the (separate) buffers —
                # but NULL is not an offset: both-NULL must compare EQUAL, and a
                # NULL-vs-nonNULL mismatch must fail. Without the NULL guard every
                # not-found return (ro==rd==0) computed -so != -sd and falsely failed.
                L.append('      char* ro=(char*)fo(%s); char* rd=(char*)fd(%s); if((ro==0)!=(rd==0)) ok=0; else if(ro!=0 && (ro-(char*)%s)!=(rd-(char*)%s)) ok=0;' % (",".join(argo), ",".join(argd), firstp[0], firstp[1]))
            else:
                L.append('      void* ro=(void*)fo(%s); void* rd=(void*)fd(%s); if((ro==0)!=(rd==0)) ok=0;' % (",".join(argo), ",".join(argd)))
        else:
            L.append('      int ro=(int)fo(%s), rd=(int)fd(%s); if(ro!=rd) ok=0;' % (",".join(argo), ",".join(argd)))
        L += post
        L.append('      if(!ok){fails++;}')
        L.append('    }')
        L.append('    if(fails){printf("FAIL %s  %%d/%d\\n",fails); total_fail++;} else printf("PASS %s\\n");' % (name, N, name))
        L.append('    }')
        L.append('  }')
        tested += 1
    L.append('  printf("== %s: %%d functions, %%d failing ==\\n", %d, total_fail);' % (dll, tested))
    L.append('  return total_fail;')
    L.append('}')
    return "\n".join(L)

def cl(args, log):
    with open(log, "w") as lf:
        subprocess.run(["cl"] + args, cwd=WORK, stdout=lf, stderr=subprocess.STDOUT)

def main():
    import concurrent.futures, shutil
    setup_msvc_env()
    # Kill any lingering driver processes from a prior run (a hung driver that was
    # timeout-killed can keep a dec_*.dll handle open, locking the file so the next
    # compile silently fails and tests run against the STALE, broken DLL).
    subprocess.run(["taskkill", "/F", "/IM", "drv_*.exe"], capture_output=True)
    sigs = parse_sigs()
    items = []
    for dll in DLLS:
        cfile = os.path.join(DECOMP, dll + ".c")
        if not os.path.exists(cfile):
            continue
        manifest = os.path.join(DECOMP, dll + ".manifest")
        names = [l.split("\t")[0] for l in open(manifest).read().splitlines() if l.strip()] if os.path.exists(manifest) else list(sigs)
        deff = os.path.join(WORK, "dec_%s.def" % dll)
        open(deff, "w").write("EXPORTS\n" + "\n".join(names) + "\n")
        # Delete prior build artifacts so a FAILED recompile can't silently leave a
        # stale DLL/exe behind (which would test the old, possibly-broken code and
        # report bogus failures). os.path.exists then truly means "compiled now".
        for art in ("dec_%s.dll" % dll, "drv_%s.exe" % dll):
            p = os.path.join(WORK, art)
            if os.path.exists(p):
                try: os.remove(p)
                except OSError: pass
        open(os.path.join(WORK, "driver_%s.cpp" % dll), "w").write(gen_driver(dll, sigs.get(dll, {}), names))
        shutil.copy(os.path.join(CORPUS, dll + ".dll"), os.path.join(WORK, dll + ".dll"))
        items.append((dll, cfile, deff))

    # Parallel compile: every decompiled DLL + every driver at once across cores.
    jobs = []
    for dll, cfile, deff in items:
        jobs.append((["/nologo", "/LD", "/Od", "/w", "/Fe:dec_%s.dll" % dll, cfile, "/link", "/DEF:" + deff],
                     os.path.join(WORK, "cl_%s.log" % dll)))
        jobs.append((["/nologo", "/Od", "/w", "/EHsc", "/Fe:drv_%s.exe" % dll, os.path.join(WORK, "driver_%s.cpp" % dll)],
                     os.path.join(WORK, "cld_%s.log" % dll)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=14) as ex:
        list(ex.map(lambda j: cl(j[0], j[1]), jobs))

    grand = collections.Counter()
    tot_pass = tot_fail = 0
    for dll, cfile, deff in items:
        if not os.path.exists(os.path.join(WORK, "dec_%s.dll" % dll)):
            print("=== %s: DECOMPILED C FAILED TO COMPILE ===" % dll)
            for line in open(os.path.join(WORK, "cl_%s.log" % dll), errors="replace").read().splitlines():
                if "error" in line.lower(): print("   ", line)
            grand[dll + "_compilefail"] += 1
            continue
        exe = os.path.join(WORK, "drv_%s.exe" % dll)
        if not os.path.exists(exe):
            print("=== %s: DRIVER FAILED TO COMPILE ===" % dll)
            for line in open(os.path.join(WORK, "cld_%s.log" % dll), errors="replace").read().splitlines():
                if "error" in line.lower(): print("   ", line)
            continue
        try:
            out = subprocess.run([exe], capture_output=True, text=True, cwd=WORK, timeout=120)
            stdout = out.stdout
            hung = ""
        except subprocess.TimeoutExpired as e:
            # A decompiled function infinite-looped. Recover partial stdout so the
            # last "testing <fn>" line names the culprit, and report it as a fail.
            stdout = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, (bytes, bytearray)) else (e.stdout or "")
            seen = [l for l in stdout.splitlines() if l.startswith("PASS ") or l.startswith("FAIL") or l.startswith("MISS ") or l.startswith("RUN ")]
            hung = seen[-1].split()[-1] if seen else "?"
        passes = stdout.count("PASS ")
        fails = [l for l in stdout.splitlines() if l.startswith("FAIL") or l.startswith("MISS")]
        if hung:
            fails.append("HANG (infinite loop) after %s" % hung)
        tot_pass += passes; tot_fail += len(fails)
        print("=== %s: %d PASS, %d FAIL%s ===" % (dll, passes, len(fails), "  *HUNG*" if hung else ""))
        for l in fails[:40]: print("   ", l)
        grand[dll] = (passes, len(fails))
    print("\n==== SUMMARY: %d PASS / %d FAIL across %d files ====" % (tot_pass, tot_fail, len(items)))
    for k, v in grand.items():
        if "compilefail" in str(k): print("  COMPILE-FAIL", k)

if __name__ == "__main__":
    main()
