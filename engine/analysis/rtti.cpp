/*
 * rtti.cpp — ds_engine_scan_rtti(): recover C++ class names from MSVC x64 RTTI.
 *
 * MSVC emits, for every polymorphic class, a vtable preceded (8 bytes before
 * vtable[0]) by a pointer to an RTTICompleteObjectLocator (COL), which points to
 * a TypeDescriptor carrying the decorated class name (".?AVFoo@@"). This pass
 * scans read-only data segments for that structure, validates it strongly (the
 * x64 COL signature==1 AND the pSelf self-reference), demangles the class name,
 * and seeds e->symbols with "<Class>__vftbl_<i>" for every virtual-function slot
 * that is a recovered, still-unnamed function. It runs BEFORE the naming loop in
 * ds_engine_resolve_symbols, so the seeded names win as priority-1 seeded symbols
 * at BOTH the function definition (self name) and every call site (name_for_rva).
 * Gated by DS_NO_RTTI; x64-only (the x86 COL has no pSelf and a 20-byte layout).
 *
 * x64 VA/RVA discipline (the dominant failure mode): the meta-qword, the vtable
 * slots and TypeDescriptor.pVFTable are FULL 64-bit VAs (subtract e->base); every
 * cross-ref INSIDE the COL is already a 32-bit RVA (used directly). Every read is
 * bounds-checked against e->image_size and only 8-aligned candidates are scanned.
 * All offsets were empirically confirmed against a purpose-built RTTI DLL.
 */
#include "disasm.h"
#include "engine_internal.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <set>
#include <map>

namespace {

/* bounds-checked little-endian reads over the flat RVA-indexed image. */
bool read_u32(const ds_engine* e, uint64_t rva, uint32_t& out) {
    if (rva + 4 > e->image_size) return false;
    std::memcpy(&out, e->image + rva, 4);
    return true;
}
bool read_u64(const ds_engine* e, uint64_t rva, uint64_t& out) {
    if (rva + 8 > e->image_size) return false;
    std::memcpy(&out, e->image + rva, 8);
    return true;
}

/* read a NUL-terminated, printable decorated name at `rva`, or "" if it is not
 * a plausible name (non-printable byte, or no NUL within the bound). */
std::string read_rtti_name(const ds_engine* e, uint64_t rva) {
    std::string s;
    for (uint64_t i = 0; i < 512 && rva + i < e->image_size; ++i) {
        char c = (char)e->image[rva + i];
        if (c == '\0') return s;
        if (c < 0x20 || c > 0x7e) return "";
        s.push_back(c);
    }
    return "";
}

bool already_seeded(const ds_engine* e, uint64_t rva) {
    for (size_t i = 0; i < e->symbol_len; ++i)
        if (e->symbols[i].rva == rva && e->symbols[i].name[0]) return true;
    return false;
}

/* MSVC RTTI <class-type> name demangler with NAMESPACE + TEMPLATE support.
 * The decorated name is ".?A<tag><qualified-name>@@": tag V=class U=struct W=enum T=union;
 * the qualified name is innermost-first, '@'-separated, '@@'-terminated. A TEMPLATE component
 * is `?$<name>@<type-args>@` (each arg a builtin type code or a nested class ref), so
 * ".?AV?$Box@H@mytools@@" -> "mytools::Box<int>". Recursive-descent; on an unhandled shape it
 * sets ok=false and the caller falls back to the flat @-split. */
struct MsvcName {
    const std::string& s; size_t i; bool ok = true;
    MsvcName(const std::string& str, size_t st) : s(str), i(st) {}
    char peek() const { return i < s.size() ? s[i] : '\0'; }
    std::string ident() {                        /* chars up to '@', consuming the '@' */
        std::string id;
        while (i < s.size() && s[i] != '@') id += s[i++];
        if (i < s.size()) i++;
        return id;
    }
    std::string builtin() {                      /* one template type-arg if a simple builtin, else "" */
        char c = peek();
        if (c == '_') {
            char d = (i + 1 < s.size()) ? s[i + 1] : '\0';
            const char* r = (d=='J')?"__int64":(d=='K')?"unsigned __int64":(d=='N')?"bool":(d=='W')?"wchar_t":nullptr;
            if (r) { i += 2; return r; }
            return "";
        }
        const char* r = nullptr;
        switch (c) {
            case 'D': r="char"; break; case 'C': r="signed char"; break; case 'E': r="unsigned char"; break;
            case 'F': r="short"; break; case 'G': r="unsigned short"; break;
            case 'H': r="int"; break; case 'I': r="unsigned int"; break;
            case 'J': r="long"; break; case 'K': r="unsigned long"; break;
            case 'M': r="float"; break; case 'N': r="double"; break; case 'O': r="long double"; break;
            case 'X': r="void"; break;
        }
        if (r) { i++; return r; }
        return "";
    }
    std::string number() {                       /* MSVC int literal, already past "$0" */
        bool neg = false; if (peek()=='?') { neg=true; ++i; }
        if (peek()>='0' && peek()<='9') {        /* 1..10 encoded as '0'..'9' */
            long v=(peek()-'0')+1; ++i; return (neg?"-":"")+std::to_string(v);
        }
        long v=0; bool any=false;                /* >10: nibbles 'A'..'P', '@'-terminated */
        while (peek()>='A' && peek()<='P') { v=v*16+(peek()-'A'); ++i; any=true; }
        if (peek()=='@') ++i;
        if (!any) { ok=false; return "?"; }
        return (neg?"-":"")+std::to_string(v);
    }
    std::string type_arg() {                     /* a template argument */
        static const bool off = std::getenv("DS_NO_TMPLARG") != nullptr;
        if (off) {                               /* old behaviour: builtins/classes only */
            std::string b0 = builtin();
            if (!b0.empty()) return b0;
            char c0 = peek();
            if (c0 == 'V' || c0 == 'U' || c0 == 'T') { i++; return qname(); }
            if (c0 == 'W') { i++; if (peek()=='4') i++; return qname(); }
            ok = false; return "?";
        }
        /* Peel pointer (P/Q/R/S) / reference (A/B) layers, each optionally __ptr64 'E' + a
         * cv byte A-D; then non-type integer args ($0<num>); then builtins/classes. */
        std::string suffix;
        for (;;) { char c = peek();
            if (c=='P'||c=='Q'||c=='R'||c=='S') { ++i; if(peek()=='E')++i; if(peek()>='A'&&peek()<='D')++i; suffix="*"+suffix; continue; }
            if (c=='A'||c=='B')                 { ++i; if(peek()=='E')++i; if(peek()>='A'&&peek()<='D')++i; suffix="&"+suffix; continue; }
            break;
        }
        if (peek()=='$') { ++i; if (peek()=='0') { ++i; return number(); } ok=false; return "?"; }
        std::string b = builtin();
        if (!b.empty()) return b + suffix;
        char c = peek();
        if (c == 'V' || c == 'U' || c == 'T') { i++; return qname() + suffix; }   /* class/struct/union arg */
        if (c == 'W') { i++; if (peek()=='4') i++; return qname() + suffix; }      /* enum: W4<name> */
        ok = false; return "?";                  /* genuinely unknown: degrade */
    }
    std::string qname() {                        /* qualified name up to '@@' */
        std::vector<std::string> comps;
        while (i < s.size() && ok) {
            if (peek() == '@') { i++; break; }   /* the second '@' of '@@' -> name end */
            if (peek() == '?' && i + 1 < s.size() && s[i + 1] == '$') {   /* template component */
                i += 2;
                std::string tn = ident();        /* template name (up to '@') */
                std::string args; bool first = true;
                while (i < s.size() && peek() != '@' && ok) {
                    if (!first) args += ", "; first = false;
                    args += type_arg();
                }
                if (i < s.size()) i++;            /* consume the '@' closing the arg list */
                comps.push_back(tn + "<" + args + ">");
            } else {
                comps.push_back(ident());
            }
        }
        std::string out;                          /* innermost-first -> reverse, join with :: */
        for (size_t k = comps.size(); k-- > 0; ) {
            if (comps[k].empty()) continue;
            if (!out.empty()) out += "::";
            out += comps[k];
        }
        return out;
    }
};

std::string demangle(const std::string& dec, bool* is_struct = nullptr) {
    if (dec.rfind(".?A", 0) != 0 || dec.size() < 5) return "";
    if (is_struct) *is_struct = (dec[3] == 'U' || dec[3] == 'T');   /* U=struct T=union vs V=class */
    MsvcName p(dec, 4);
    std::string out = p.qname();
    if (p.ok && !out.empty()) return out;
    /* fallback: flat @-split (handles shapes the parser declines, e.g. exotic std:: templates) */
    std::string body = dec.substr(4);
    size_t at = body.rfind("@@");
    if (at != std::string::npos) body = body.substr(0, at);
    std::vector<std::string> parts; std::string cur;
    for (char c : body) { if (c == '@') { parts.push_back(cur); cur.clear(); } else cur.push_back(c); }
    parts.push_back(cur);
    out.clear();
    for (size_t k = parts.size(); k-- > 0; ) {
        if (parts[k].empty()) continue;
        if (!out.empty()) out += "::";
        out += parts[k];
    }
    return out;
}

/* rewrite to a valid C identifier: "::" -> "__", any other non-[A-Za-z0-9_] -> '_'.
 * Keeps seeded names compile-safe in the standalone TU (anonymous namespaces
 * `?A0x..`, templates `?$..`, and operators collapse to underscores). */
std::string c_safe(const std::string& s) {
    std::string o;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == ':' && i + 1 < s.size() && s[i + 1] == ':') { o += "__"; ++i; }
        else if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') || c == '_') o += c;
        else o += '_';
    }
    return o;
}

/* ============================ G++ / Itanium ABI RTTI ============================
 * MinGW/g++ (Itanium C++ ABI) lays out, for a polymorphic class:
 *   _ZTS<mangled>  type-name string:  "<len><name>"  or  "N<len><name>..E" (nested)
 *   _ZTI<mangled>  type_info object:  [0]=&(type_info's own vtable)  [1]=&_ZTS  [2..]=bases
 *   _ZTV<mangled>  vtable:            [0]=offset-to-top(0)  [1]=&_ZTI  [2..]=virtual fns
 * An object stores, at +0, the address of vtable slot [2] (vtbl_rva + 2*8), NOT the base.
 * These names are usually NOT exported from a -shared DLL, so detect by STRUCTURE:
 *   type-string  <--(name ptr)--  _ZTI  <--(typeinfo ptr)--  _ZTV  -->  vfuncs (exec)
 * Anchored on the mangled type-name string (a very specific byte pattern), then walk the
 * two pointer back-links via a VA->positions index built once over read-only data. */

/* Itanium demangler for the _ZTS payload (a <class-type> mangling), with NAMESPACE + TEMPLATE
 * support (outermost-first, unlike MSVC):
 *   simple    <len><name>                  -> "name"
 *   nested    N <comp> ... E                -> "a::b::c"
 *   template  <len><name> I <args> E        -> "name<int, ...>"   (each arg a builtin or a name)
 * Only <source-name> components + builtin/name template args; declines (ok=false -> "") on any
 * other production (pointers, substitutions, cv-qualifiers) so we never mis-name. */
struct ItaniumName {
    const std::string& s; size_t i = 0; bool ok = true;
    ItaniumName(const std::string& str) : s(str) {}
    char peek() const { return i < s.size() ? s[i] : '\0'; }
    std::string builtin() {                       /* one <builtin-type> code, or "" */
        static const struct { char c; const char* n; } B[] = {
            {'v',"void"},{'b',"bool"},{'c',"char"},{'a',"signed char"},{'h',"unsigned char"},
            {'s',"short"},{'t',"unsigned short"},{'i',"int"},{'j',"unsigned int"},{'l',"long"},
            {'m',"unsigned long"},{'x',"long long"},{'y',"unsigned long long"},{'f',"float"},
            {'d',"double"},{'e',"long double"},{'w',"wchar_t"} };
        for (auto& b : B) if (peek() == b.c) { ++i; return b.n; }
        return "";
    }
    std::string source_name() {                   /* <len><chars>, optionally `I<args>E` */
        if (peek() < '1' || peek() > '9') { ok = false; return ""; }
        size_t len = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') { len = len*10 + (size_t)(s[i]-'0'); ++i; }
        if (len == 0 || i + len > s.size()) { ok = false; return ""; }
        std::string nm = s.substr(i, len);
        for (char c : nm)
            if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_')) { ok = false; return ""; }
        i += len;
        if (peek() == 'I') {                       /* template-args */
            ++i;
            std::string args; bool first = true;
            while (i < s.size() && peek() != 'E' && ok) {
                if (!first) args += ", "; first = false;
                args += type_arg();
            }
            if (peek() == 'E') ++i; else ok = false;
            nm += "<" + args + ">";
        }
        return nm;
    }
    std::string type_arg() {                       /* a template argument */
        static const bool tmoff = std::getenv("DS_NO_TMPLARG") != nullptr;
        if (tmoff) {
            std::string b0 = builtin();
            if (!b0.empty()) return b0;
            if (peek() == 'N') return nested();
            if (peek() >= '1' && peek() <= '9') return source_name();
            ok = false; return "?";
        }
        /* Peel pointer 'P'->'*', reference 'R'->'&', 'O'->'&&', dropping cv prefixes K/V/r;
         * handle 'L'<type><value>'E' integer literals; then builtins/nested/source-name. */
        std::string suffix;
        for (;;) { char c = peek();
            if (c=='P') { ++i; suffix="*"+suffix; continue; }
            if (c=='R') { ++i; suffix="&"+suffix; continue; }
            if (c=='O') { ++i; suffix="&&"+suffix; continue; }
            if (c=='K'||c=='V'||c=='r') { ++i; continue; }   /* cv-qualifier prefix: drop */
            break;
        }
        if (peek()=='L') {                         /* literal: L <type> <value> E */
            ++i; builtin();                        /* consume the type code */
            std::string num; bool neg=false;
            if (peek()=='n') { neg=true; ++i; }
            while (peek()>='0' && peek()<='9') { num+=peek(); ++i; }
            if (peek()=='E') ++i;
            return num.empty() ? std::string("?") : (neg?"-":"")+num;
        }
        std::string b = builtin();
        if (!b.empty()) return b + suffix;
        if (peek() == 'N') return nested() + suffix;
        if (peek() >= '1' && peek() <= '9') return source_name() + suffix;
        ok = false; return "?";                    /* subst/other: degrade */
    }
    std::string nested() {                          /* N <comp>... E  (outermost-first) */
        if (peek() != 'N') { ok = false; return ""; }
        ++i;
        std::vector<std::string> parts;
        while (i < s.size() && peek() != 'E' && ok) parts.push_back(source_name());
        if (peek() == 'E') ++i; else ok = false;
        std::string out;
        for (size_t k = 0; k < parts.size(); ++k) { if (k) out += "::"; out += parts[k]; }
        return out;
    }
    std::string parse() { return peek() == 'N' ? nested() : source_name(); }
};

std::string itanium_demangle(const std::string& s) {
    ItaniumName p(s);
    std::string out = p.parse();
    if (!p.ok || out.empty() || p.i != s.size()) return "";
    return out;
}

void scan_rtti_itanium(ds_engine* e) {
    /* index: in-image VA -> 8-aligned rodata RVAs whose qword == that VA (the back-link
     * relation we need). Only pointers landing inside the image are recorded. */
    std::vector<std::pair<uint64_t,uint64_t>> ptrs;           /* (VA value, rva position) */
    for (size_t si = 0; si < e->segment_len; ++si) {
        const ds_segment& s = e->segments[si];
        if (!(s.flags & DS_FLAG_R) || (s.flags & DS_FLAG_X)) continue;
        uint64_t start = (s.rva + 7) & ~7ull, end = s.rva + s.size;
        if (end > e->image_size) end = e->image_size;
        for (uint64_t pos = start; pos + 8 <= end; pos += 8) {
            uint64_t v; if (!read_u64(e, pos, v)) continue;
            if (v >= e->base && v - e->base < e->image_size) ptrs.push_back({ v, pos });
        }
    }
    auto find_refs = [&](uint64_t va, std::vector<uint64_t>& out) {
        for (auto& pr : ptrs) if (pr.first == va) out.push_back(pr.second);
    };

    for (size_t si = 0; si < e->segment_len; ++si) {
        const ds_segment& s = e->segments[si];
        if (!(s.flags & DS_FLAG_R) || (s.flags & DS_FLAG_X)) continue;
        uint64_t start = s.rva, end = s.rva + s.size;
        if (end > e->image_size) end = e->image_size;
        for (uint64_t p = start; p < end; ++p) {
            /* string START: segment start, or byte after a NUL; first byte a length digit or 'N' */
            if (p != start && e->image[p - 1] != 0) continue;
            char c0 = (char)e->image[p];
            if (!((c0 >= '1' && c0 <= '9') || c0 == 'N')) continue;
            std::string str = read_rtti_name(e, p);           /* NUL-terminated printable, or "" */
            if (str.size() < 2) continue;
            std::string cls_raw = itanium_demangle(str);       /* RAW: "game::Pool<int>" (namespaces/templates) */
            if (cls_raw.empty()) continue;
            std::string cls = c_safe(cls_raw);                  /* identifier form for vtbl-slot fn names */

            std::vector<uint64_t> ti_name_slots; find_refs(e->base + p, ti_name_slots);
            for (uint64_t ns : ti_name_slots) {               /* _ZTI whose +8 name-slot -> this string */
                if (ns < 8) continue;
                uint64_t ti_rva = ns - 8;
                uint64_t tivt;                                /* typeinfo[0] = its own vtable ptr. It is often
                 * IMPORTED (__class_type_info's vtable lives in libstdc++), so it may be an IAT/thunk
                 * pointer rather than in-image — only require a readable, non-null qword here. The real
                 * filter is the string<-ti<-vtable double back-link plus the exec-vfunc check below. */
                if (!read_u64(e, ti_rva, tivt) || tivt == 0) continue;
                /* TYPEID (Itanium): seed the _ZTI address a static g++ typeid references. */
                if (!std::getenv("DS_NO_TYPEID") && !already_seeded(e, ti_rva)) {
                    char ti[176]; std::snprintf(ti, sizeof ti, "%s__type_info", cls.c_str());
                    ds_engine_add_symbol(e, ti_rva, ti);
                }

                std::vector<uint64_t> vt_ti_slots; find_refs(e->base + ti_rva, vt_ti_slots);
                for (uint64_t vs : vt_ti_slots) {             /* _ZTV whose +8 typeinfo-slot -> this typeinfo */
                    if (vs < 8) continue;
                    uint64_t vtbl_rva = vs - 8;               /* [0]=offset-to-top, [1]=&_ZTI */
                    uint64_t otop;                            /* offset-to-top: 0 (primary) or small negative */
                    if (!read_u64(e, vtbl_rva, otop)) continue;
                    int64_t sotop = (int64_t)otop;
                    if (sotop > 0 || sotop < -(int64_t)e->image_size) continue;
                    uint64_t vfun_rva = vtbl_rva + 16;        /* slot [2]: first virtual fn; objects store its VA */
                    uint64_t v0;
                    if (!read_u64(e, vfun_rva, v0) || v0 < e->base || !ds_rva_is_exec(e, v0 - e->base)) continue;

                    /* Name `<Class>__vftable` ONLY on the PRIMARY vtable (offset-to-top 0):
                     * that is the vtable an object stores at +0, which is what class_for_vtable
                     * matches to recognize a constructor. A secondary (MI base-subobject) vtable
                     * has a negative offset-to-top and lives at a sub-object offset, so naming it
                     * `<Class>__vftable` would be wrong; its virtuals are still named below. */
                    if (sotop == 0 && !already_seeded(e, vfun_rva)) {   /* name the vtable at &slot[2] (RAW name) */
                        char vt[160]; std::snprintf(vt, sizeof vt, "%s__vftable", cls_raw.c_str());
                        ds_engine_add_symbol(e, vfun_rva, vt);
                    }
                    for (int i = 0; i < 4096; ++i) {
                        uint64_t v;
                        if (!read_u64(e, vfun_rva + 8 * (uint64_t)i, v) || v < e->base) break;
                        uint64_t fn = v - e->base;
                        if (!ds_rva_is_exec(e, fn)) break;
                        if (!already_seeded(e, fn)) {
                            char nm[96]; std::snprintf(nm, sizeof nm, "%s__vftbl_%d", cls.c_str(), i);
                            ds_engine_add_symbol(e, fn, nm);
                        }
                    }
                }
            }
        }
    }
}

/* ---- ctor/dtor detection helpers (Intel operand-string parsers over ds_insn) ---- */
std::string first_reg_tok(const char* p) {          /* leading register token: [a-z0-9]+ */
    std::string r; while (*p == ' ') ++p;
    while ((*p>='a'&&*p<='z')||(*p>='0'&&*p<='9')) r += *p++;
    return r;
}
bool reg_reg(const char* ops, std::string& d, std::string& s) {  /* "rbx, rcx" (no mem) */
    if (std::strchr(ops, '[')) return false;
    const char* comma = std::strchr(ops, ','); if (!comma) return false;
    d = first_reg_tok(ops);
    const char* p = comma + 1; while (*p==' ') ++p;
    s = first_reg_tok(p);
    return !d.empty() && !s.empty();
}
bool store_base0(const char* ops, std::string& base, std::string& src) { /* "qword ptr [rbx], rax" */
    const char* comma = std::strchr(ops, ','); if (!comma) return false;
    const char* lb = std::strchr(ops, '['); if (!lb || lb > comma) return false;
    const char* rb = std::strchr(lb, ']'); if (!rb || rb > comma) return false;
    for (const char* q = lb + 1; q < rb; ++q) if (*q=='+'||*q=='-'||*q=='*') return false; /* [reg] only */
    base = first_reg_tok(lb + 1); if (base.empty()) return false;
    const char* p = comma + 1; while (*p==' ') ++p;
    src = first_reg_tok(p);
    return !src.empty();
}
std::string class_for_vtable_va(const ds_engine* e, uint64_t va) {   /* &<Class>__vftable -> tag */
    if (!va) return "";
    for (uint64_t r : { va, (va >= e->base ? va - e->base : va) })
        for (size_t i = 0; i < e->symbol_len; ++i) {
            if (e->symbols[i].rva != r || !e->symbols[i].name[0]) continue;
            std::string n = e->symbols[i].name;
            for (const char* suf : { "__vftable", "__vfstruct" }) {
                size_t sl = std::strlen(suf);
                if (n.size() > sl && n.compare(n.size()-sl, sl, suf) == 0)
                    return c_safe(n.substr(0, n.size()-sl));
            }
        }
    return "";
}
size_t vtbl_slot_sym(const ds_engine* e, uint64_t r) {   /* is func rva a __vftbl_N slot? */
    for (size_t i = 0; i < e->symbol_len; ++i)
        if (e->symbols[i].rva == r && e->symbols[i].name[0] &&
            std::strstr(e->symbols[i].name, "__vftbl_")) return i;
    return SIZE_MAX;
}
bool name_in_use(const ds_engine* e, const char* nm) {
    for (size_t i = 0; i < e->symbol_len; ++i)
        if (e->symbols[i].name[0] && !std::strcmp(e->symbols[i].name, nm)) return true;
    return false;
}
/* Does the string at `addr` (VA or RVA) parse as a printf/scanf FORMAT string, i.e. contain
 * at least one real `%<conv>` conversion? The universal signal that a callee is a
 * formatted-I/O function, independent of symbols/FLIRT/CRT-linkage. */
bool looks_like_fmt_string(const ds_engine* e, uint64_t addr, bool* has_s = nullptr) {
    uint64_t rva = (addr >= e->base) ? addr - e->base : addr;
    if (rva == 0 || rva >= e->image_size) return false;
    int conv = 0; bool pcts = false;
    for (uint64_t i = 0; i < 300; ++i) {
        if (rva + i >= e->image_size) return false;
        unsigned char c = e->image[rva + i];
        if (c == 0) break;
        if (!((c >= 0x20 && c <= 0x7e) || c=='\t' || c=='\n' || c=='\r')) return false;
        if (c == '%') {
            uint64_t j = i + 1;
            if (rva + j < e->image_size && e->image[rva + j] == '%') { i = j; continue; }  /* %% */
            while (rva + j < e->image_size &&
                   std::strchr("-+ 0#*.0123456789lhjztLI", (char)e->image[rva + j])) ++j;
            if (rva + j < e->image_size) {
                char cc = (char)e->image[rva + j];
                if (std::strchr("diouxXeEfFgGaAcspn", cc)) { ++conv; if (cc == 's') pcts = true; }
            }
        }
    }
    if (has_s) *has_s = pcts;
    return conv >= 1;
}

/* NON-POLYMORPHIC typeid: the COL scan only visits polymorphic classes' TypeDescriptors, so
 * `typeid(PlainStruct)` (a type with no vtable/COL) had no address->class mapping. Scan the
 * read-only data for the `.?A<tag>...@@` decorated name a TypeDescriptor carries at +16, and
 * seed `<Class>__type_info` (at TD+8, the typeid operand) and `<Class>__typedesc` (at TD, the
 * dynamic_cast dst arg) for every one -- polymorphic or not. Bounded byte scan; the `.?AV`/
 * `.?AU` prefix is RTTI-specific so false positives are negligible and, being unreferenced,
 * harmless. DS_NO_TYPEID. */
void scan_rtti_typedescriptors(ds_engine* e) {
    if (std::getenv("DS_NO_TYPEID")) return;
    bool no_dc = std::getenv("DS_NO_DYNCAST") != nullptr;
    for (size_t si = 0; si < e->segment_len; ++si) {
        const ds_segment& s = e->segments[si];
        if (!(s.flags & DS_FLAG_R) || (s.flags & DS_FLAG_X)) continue;
        uint64_t start = s.rva, end = s.rva + s.size;
        if (end > e->image_size) end = e->image_size;
        for (uint64_t p = start; p + 4 <= end; ++p) {
            if (e->image[p] != '.' || e->image[p+1] != '?' || e->image[p+2] != 'A') continue;
            char tag = (char)e->image[p+3];
            if (tag != 'V' && tag != 'U' && tag != 'W' && tag != 'T') continue;
            if (p < 16) continue;                              /* need TD base = p - 16 */
            std::string dec = read_rtti_name(e, p);
            if (dec.size() < 5 || dec.rfind(".?A", 0) != 0) continue;
            uint64_t td = p - 16, vft;
            if (!read_u64(e, td, vft) || vft == 0) continue;   /* TD.pVFTable must be present */
            bool is_struct = false;
            std::string cls_raw = demangle(dec, &is_struct);
            if (cls_raw.empty()) continue;
            std::string cls = c_safe(cls_raw);
            if (!already_seeded(e, td + 8)) {
                char ti[176]; std::snprintf(ti, sizeof ti, "%s__type_info", cls.c_str());
                ds_engine_add_symbol(e, td + 8, ti);
            }
            if (!no_dc && !already_seeded(e, td)) {
                char nm[176]; std::snprintf(nm, sizeof nm, "%s__typedesc", cls.c_str());
                ds_engine_add_symbol(e, td, nm);
            }
            p += dec.size();                                   /* skip past this name */
        }
    }
}

/* PURE VIRTUAL: the abstract-call trap (`_purecall`/`__cxa_pure_virtual`) is the ONE code
 * address MSVC stores into >=2 vtable slots at DISTINCT indices (a real, even inherited,
 * method sits at ONE index across base+derived vtables). Re-run the exact COL recognition
 * and return the rvas that occupy >=2 distinct slot indices. Proven: {} on NullWare. */
std::set<uint64_t> collect_purecall_rvas(ds_engine* e) {
    std::map<uint64_t, std::set<int>> idx;
    for (size_t si = 0; si < e->segment_len; ++si) {
        const ds_segment& s = e->segments[si];
        if (!(s.flags & DS_FLAG_R) || (s.flags & DS_FLAG_X)) continue;
        uint64_t start = (s.rva + 7) & ~7ull, end = s.rva + s.size;
        if (end > e->image_size) end = e->image_size;
        for (uint64_t pos = start + 8; pos + 8 <= end; pos += 8) {
            uint64_t metaVA;
            if (!read_u64(e, pos - 8, metaVA) || metaVA < e->base) continue;
            uint64_t col = metaVA - e->base;
            const ds_segment* cs = ds_seg_for_rva(e, col);
            if (!cs || (cs->flags & DS_FLAG_X)) continue;
            uint32_t sig, self, ptd;
            if (!read_u32(e, col+0x00, sig)  || sig != 1) continue;
            if (!read_u32(e, col+0x14, self) || self != (uint32_t)col) continue;
            if (!read_u32(e, col+0x0C, ptd)  || !ds_rva_is_mapped(e, ptd) ||
                ds_rva_is_exec(e, ptd)) continue;
            for (int i = 0; i < 4096; ++i) {
                uint64_t v;
                if (!read_u64(e, pos + 8*(uint64_t)i, v) || v < e->base) break;
                uint64_t fn = v - e->base;
                if (!ds_rva_is_exec(e, fn)) break;
                idx[fn].insert(i);
            }
        }
    }
    std::set<uint64_t> pure;
    for (auto& kv : idx) if (kv.second.size() >= 2) pure.insert(kv.first);
    return pure;
}

} // namespace

extern "C" void ds_engine_scan_rtti(ds_engine* e) {
    static const bool off = std::getenv("DS_NO_RTTI") != nullptr;
    if (off || !e || e->arch != DS_ARCH_X64 || !e->image) return;
    static const bool no_pure = std::getenv("DS_NO_PUREVIRT") != nullptr;
    std::set<uint64_t> purecall = no_pure ? std::set<uint64_t>{} : collect_purecall_rvas(e);

    for (size_t si = 0; si < e->segment_len; ++si) {
        const ds_segment& s = e->segments[si];
        if (!(s.flags & DS_FLAG_R) || (s.flags & DS_FLAG_X)) continue;  /* read-only data */
        uint64_t start = (s.rva + 7) & ~7ull, end = s.rva + s.size;
        if (end > e->image_size) end = e->image_size;
        for (uint64_t pos = start + 8; pos + 8 <= end; pos += 8) {
            /* the qword before a vtable candidate is a VA of its COL */
            uint64_t metaVA;
            if (!read_u64(e, pos - 8, metaVA) || metaVA < e->base) continue;
            uint64_t col = metaVA - e->base;
            const ds_segment* cs = ds_seg_for_rva(e, col);
            if (!cs || (cs->flags & DS_FLAG_X)) continue;
            uint32_t sig, self, ptd, offc;
            if (!read_u32(e, col + 0x00, sig)  || sig != 1) continue;              /* x64 signature */
            if (!read_u32(e, col + 0x14, self) || self != (uint32_t)col) continue; /* pSelf self-ref */
            if (!read_u32(e, col + 0x0C, ptd)  || !ds_rva_is_mapped(e, ptd) ||
                ds_rva_is_exec(e, ptd)) continue;
            std::string dec = read_rtti_name(e, ptd + 0x10);   /* TypeDescriptor+0x10 */
            if (dec.rfind(".?A", 0) != 0) continue;
            uint64_t v0;                                       /* slot 0 must be code */
            if (!read_u64(e, pos, v0) || v0 < e->base || !ds_rva_is_exec(e, v0 - e->base)) continue;
            if (!read_u32(e, col + 0x04, offc)) offc = 0;      /* subobject displacement */
            bool is_struct = false;
            std::string cls_raw = demangle(dec, &is_struct);   /* RAW: "game::Entity", "game::Pool<int>" */
            if (cls_raw.empty()) continue;
            std::string cls = c_safe(cls_raw);                 /* identifier form for vtbl-slot fn names */
            /* TYPEID: seed the type_info object so a `typeid(T)` operand (a reference to
             * &TypeDescriptor._Data == ptd+8, what MSVC compares/passes to .name()) resolves
             * to `&<Class>__type_info` instead of a raw rodata address. DS_NO_TYPEID. */
            if (!std::getenv("DS_NO_TYPEID") && !already_seeded(e, ptd + 8)) {
                char ti[176]; std::snprintf(ti, sizeof ti, "%s__type_info", cls.c_str());
                ds_engine_add_symbol(e, ptd + 8, ti);
            }
            /* DYNAMIC_CAST: __RTDynamicCast's dst arg is the TypeDescriptor BASE (ptd), so seed
             * `<Class>__typedesc` there to resolve a `dynamic_cast<Class*>` target. DS_NO_DYNCAST. */
            if (!std::getenv("DS_NO_DYNCAST") && !already_seeded(e, ptd)) {
                char td[176]; std::snprintf(td, sizeof td, "%s__typedesc", cls.c_str());
                ds_engine_add_symbol(e, ptd, td);
            }
            /* Name the VTABLE itself (at `pos`, where slot 0 is — the address an object stores at +0),
             * with the RAW qualified name so the decompiler can recover `namespace X { class Y {...} }`.
             * The decompiler sani()s it for the C tag and keeps the raw form for the namespace block.
             * Only the primary (offc==0) vtable; the suffix carries the RTTI KIND (V=class -> __vftable,
             * U/T=struct -> __vfstruct) for the correct `class`/`struct` keyword. */
            if (offc == 0 && !already_seeded(e, pos)) {
                char vt[160]; std::snprintf(vt, sizeof vt, "%s%s", cls_raw.c_str(),
                                            is_struct ? "__vfstruct" : "__vftable");
                ds_engine_add_symbol(e, pos, vt);
                /* INHERITANCE: COL -> RTTIClassHierarchyDescriptor -> RTTIBaseClassArray. The
                 * array's entry [0] is the class itself; entry [1] is its DIRECT base (for the
                 * single-inheritance case the decompiler renders). Seed a marker symbol
                 * `<Class>__extends__<Base>` at the ClassHierarchyDescriptor RVA (unique per
                 * class, never a code/vtable address) so the decompiler can emit `struct D : B`
                 * and give a catch its caught type. Skipped for DS_NO_RTTIBASE. */
                uint32_t chd = 0, nbase = 0, pba = 0;
                if (!std::getenv("DS_NO_RTTIBASE") &&
                    read_u32(e, col + 0x10, chd) && ds_rva_is_mapped(e, chd) &&
                    read_u32(e, chd + 0x08, nbase) && nbase >= 2 && nbase < 64 &&
                    read_u32(e, chd + 0x0C, pba) && ds_rva_is_mapped(e, pba)) {
                    /* MULTIPLE INHERITANCE: walk the WHOLE BaseClassArray. base[0] is the class
                     * itself; each DIRECT base is the next entry after skipping the previous
                     * direct base's numContainedBases (BCD+0x04) indirect descendants. For each
                     * direct base seed `<Class>__extends__<Base>` (at the base's BCD rva, unique);
                     * when its PMD.mdisp (BCD+0x08) > 0 (a non-primary MI subobject) also seed
                     * `<Class>__baseoff_<mdisp>__<Base>` so an adjustor thunk can name the base. */
                    for (uint32_t k = 1; k < nbase; ) {
                        uint32_t bcd = 0, btd = 0, ncont = 0, md = 0, pdisp = 0;
                        if (!read_u32(e, pba + 4 * k, bcd) || !ds_rva_is_mapped(e, bcd)) break;
                        read_u32(e, bcd + 0x04, ncont);
                        read_u32(e, bcd + 0x00, btd);
                        read_u32(e, bcd + 0x08, md);
                        read_u32(e, bcd + 0x0C, pdisp);   /* PMD.pdisp: != -1 => VIRTUAL base */
                        bool vbase = (int32_t)pdisp != -1;
                        if (ds_rva_is_mapped(e, btd)) {
                            std::string bdec = read_rtti_name(e, btd + 0x10);
                            if (bdec.rfind(".?A", 0) == 0) {
                                std::string base_raw = demangle(bdec, nullptr);
                                if (!base_raw.empty() && base_raw != cls_raw) {
                                    char mk[224];
                                    /* virtual inheritance (`class D : virtual B`) is decidable from
                                     * the BaseClassDescriptor's PMD.pdisp (the vbtable slot); mark
                                     * it so class_bases_of renders `virtual <Base>`. */
                                    std::snprintf(mk, sizeof mk, "%s__%s__%s",
                                                  c_safe(cls_raw).c_str(),
                                                  vbase ? "vextends" : "extends",
                                                  c_safe(base_raw).c_str());
                                    ds_engine_add_symbol(e, bcd, mk);
                                    if ((int32_t)md > 0) {
                                        std::snprintf(mk, sizeof mk, "%s__baseoff_%d__%s",
                                                      c_safe(cls_raw).c_str(), (int)md,
                                                      c_safe(base_raw).c_str());
                                        ds_engine_add_symbol(e, bcd + 4, mk);
                                    }
                                }
                            }
                        }
                        k += 1 + ncont;   /* skip this direct base's indirect descendants */
                    }
                }
            }
            for (int i = 0; i < 4096; ++i) {
                uint64_t v;
                if (!read_u64(e, pos + 8 * (uint64_t)i, v) || v < e->base) break;
                uint64_t fn = v - e->base;
                if (!ds_rva_is_exec(e, fn)) break;   /* next vtable's COL-qword -> data: natural stop */
                /* PURE VIRTUAL: this slot points at the shared abstract-call trap. Name the trap
                 * `_purecall` (once) and seed a `<Class>__vftbl_N_pure` marker at the slot's data
                 * address, instead of mislabeling the trap as a real method of this class. */
                if (purecall.count(fn)) {
                    if (!already_seeded(e, fn)) ds_engine_add_symbol(e, fn, "_purecall");
                    char pk[112]; std::snprintf(pk, sizeof pk, "%s__vftbl_%d_pure", cls.c_str(), i);
                    if (!already_seeded(e, pos + 8*(uint64_t)i))
                        ds_engine_add_symbol(e, pos + 8*(uint64_t)i, pk);
                    continue;
                }
                /* Seed the name for every exec slot (not only already-recovered
                 * funcs): this pass runs BEFORE build_cfg, whose function-start
                 * seeding considers e->symbols[].rva — so a vtable-ONLY virtual
                 * (reachable solely through the vtable, never a direct call) is
                 * both recovered as a function AND named. first-writer-wins skips a
                 * slot shared by an inherited (non-overridden) virtual. */
                if (!already_seeded(e, fn)) {
                    char nm[96];
                    if (offc) std::snprintf(nm, sizeof nm, "%s_off%u__vftbl_%d", cls.c_str(), offc, i);
                    else      std::snprintf(nm, sizeof nm, "%s__vftbl_%d", cls.c_str(), i);
                    ds_engine_add_symbol(e, fn, nm);
                }
            }
        }
    }

    /* Also recover G++/MinGW (Itanium ABI) classes. Structurally disjoint from the MSVC
     * COL scan above (that keys on a sig==1 COL; this keys on _ZTS mangled-name strings),
     * so running both is safe on either compiler's output and double-seeding is guarded. */
    scan_rtti_itanium(e);
    /* also map EVERY TypeDescriptor (incl. non-polymorphic) so typeid/dynamic_cast resolve. */
    scan_rtti_typedescriptors(e);
}

/* CONSTRUCTOR / DESTRUCTOR naming. A function that stores `&<Class>__vftable` to [this+0]
 * is constructing a <Class> there (the exact rule struct_class ctor-recovery already trusts);
 * if that function is ALSO a vtable slot it is the destructor (dtors live in the vtable and
 * re-store the vtable). Name them `<Class>__ctor` / `<Class>__dtor` so call sites read as
 * such instead of fun_XXXX. Runs after scan_rtti (vtable symbols seeded) and before
 * resolve_symbols. Naming-only; DS_NO_CTORDTOR. */
extern "C" void ds_engine_scan_ctor_dtor(ds_engine* e) {
    if (std::getenv("DS_NO_CTORDTOR")) return;
    if (!e || e->arch != DS_ARCH_X64 || !e->image || !e->func_len || !e->insn_len) return;
    for (size_t fi = 0; fi < e->func_len; ++fi) {
        ds_func* f = &e->funcs[fi];
        size_t lo = 0, hi = e->insn_len;
        while (lo < hi) { size_t m=(lo+hi)/2; if (e->insns[m].rva < f->rva) lo=m+1; else hi=m; }
        uint64_t fend = f->rva + (f->size ? f->size : 0);
        std::set<std::string> thisreg = { "rcx" };        /* this + register copies of it */
        std::map<std::string,uint64_t> vtreg;             /* reg -> vtable VA it holds */
        uint64_t stored_vt = 0;
        for (size_t k = lo; k < e->insn_len && e->insns[k].rva < fend; ++k) {
            const ds_insn* in = &e->insns[k];
            std::string d, s, base;
            if (!std::strcmp(in->mnemonic,"lea") && in->ref_type==DS_REF_DATA && in->ref_target) {
                d = first_reg_tok(in->operands);
                thisreg.erase(d);
                if (!d.empty() && !class_for_vtable_va(e, in->ref_target).empty()) vtreg[d]=in->ref_target;
                else vtreg.erase(d);
            } else if (!std::strcmp(in->mnemonic,"mov") && reg_reg(in->operands, d, s)) {
                if (thisreg.count(s)) thisreg.insert(d);   /* mov rbx,rcx : rbx aliases this */
                else { thisreg.erase(d); vtreg.erase(d); }
            } else if (!std::strcmp(in->mnemonic,"mov") && store_base0(in->operands, base, s)) {
                if (thisreg.count(base) && vtreg.count(s)) stored_vt = vtreg[s];  /* last wins */
            }
        }
        if (!stored_vt) continue;
        std::string cls = class_for_vtable_va(e, stored_vt);
        if (cls.empty()) continue;
        size_t slot = vtbl_slot_sym(e, f->rva);
        char nm[96];
        std::snprintf(nm, sizeof nm, "%s__%s", cls.c_str(), slot!=SIZE_MAX ? "dtor" : "ctor");
        if (name_in_use(e, nm))
            std::snprintf(nm, sizeof nm, "%s__%s_%llx", cls.c_str(),
                          slot!=SIZE_MAX ? "dtor":"ctor", (unsigned long long)f->rva);
        if (slot != SIZE_MAX)                  /* DTOR: overwrite the __vftbl_N slot name in place */
            std::snprintf(e->symbols[slot].name, sizeof(e->symbols[slot].name), "%s", nm);
        else if (!already_seeded(e, f->rva))   /* CTOR: fun_ has no symbol -> add one */
            ds_engine_add_symbol(e, f->rva, nm);
    }
}

/* Read the string at `addr` if it is a clean, distinctive LABEL (a name a function could be
 * called after): 4..40 printable chars, >=3 letters, not a printf format, not all-digits. */
std::string read_clean_label(const ds_engine* e, uint64_t addr) {
    uint64_t rva = (addr >= e->base) ? addr - e->base : addr;
    if (rva == 0 || rva >= e->image_size) return "";
    std::string s; int alpha = 0;
    for (uint64_t i = 0; i < 48; ++i) {
        if (rva + i >= e->image_size) return "";
        unsigned char c = e->image[rva + i];
        if (c == 0) break;
        if (c < 0x20 || c > 0x7e) return "";
        if (c == '%') return "";                       /* a format string, not a label */
        if ((c>='A'&&c<='Z')||(c>='a'&&c<='z')) ++alpha;
        s += (char)c;
    }
    if (s.size() < 4 || s.size() > 40 || alpha < 3) return "";
    return s;
}

/* NAME AN ANONYMOUS FUNCTION AFTER A DISTINCTIVE STRING IT REFERENCES (Ghidra-style). When a
 * still-unnamed function references EXACTLY ONE clean label string, name it `s_<Label>` so the
 * reader sees what it is about instead of fun_XXXX. Conservative (exactly one label) to avoid
 * mislabeling a multi-string function. Runs after scan_ctor_dtor, before resolve_symbols.
 * DS_NO_STRNAME. */
extern "C" void ds_engine_scan_string_names(ds_engine* e) {
    if (std::getenv("DS_NO_STRNAME")) return;
    if (!e || e->arch != DS_ARCH_X64 || !e->image || !e->func_len || !e->insn_len) return;
    for (size_t fi = 0; fi < e->func_len; ++fi) {
        ds_func* f = &e->funcs[fi];
        bool named = false;
        for (size_t i = 0; i < e->symbol_len; ++i)
            if (e->symbols[i].rva == f->rva && e->symbols[i].name[0]) { named = true; break; }
        if (named) continue;
        size_t lo = 0, hi = e->insn_len;
        while (lo < hi) { size_t m=(lo+hi)/2; if (e->insns[m].rva < f->rva) lo=m+1; else hi=m; }
        uint64_t fend = f->rva + (f->size ? f->size : 0);
        std::set<std::string> labels;
        for (size_t k = lo; k < e->insn_len && e->insns[k].rva < fend; ++k) {
            const ds_insn* in = &e->insns[k];
            if (!std::strcmp(in->mnemonic,"lea") && in->ref_type==DS_REF_DATA && in->ref_target) {
                std::string s = read_clean_label(e, in->ref_target);
                if (!s.empty()) { labels.insert(s); if (labels.size() > 1) break; }
            }
        }
        if (labels.size() != 1) continue;
        std::string raw = c_safe(*labels.begin()), id;
        for (char c : raw) { if (c=='_' && (id.empty() || id.back()=='_')) continue; id += c; }
        while (!id.empty() && id.back() == '_') id.pop_back();   /* collapse/trim '_' runs */
        if (id.size() < 3) continue;
        if (id.size() > 28) { id.resize(28); while (!id.empty() && id.back()=='_') id.pop_back(); }
        char nm[48]; std::snprintf(nm, sizeof nm, "s_%s", id.c_str());
        if (name_in_use(e, nm)) std::snprintf(nm, sizeof nm, "s_%s_%llx", id.c_str(),
                                              (unsigned long long)f->rva);
        ds_engine_add_symbol(e, f->rva, nm);
    }
}

/* PRINT / INPUT recognition. A statically-linked CRT printf/scanf (or any user format
 * wrapper) is otherwise an anonymous fun_XXXX. The universal, compiler-independent signal is
 * the printf FORMAT-STRING calling convention: a function repeatedly called with a
 * string-literal argument that contains `%`-conversions IS a formatted-I/O function. Scan
 * every direct call, note when an arg register was loaded (in the arg-setup window) with a
 * `lea reg,[format-string]`, aggregate per callee, and name a callee hit at >=3 sites:
 * printf/fprintf (values -> output) or scanf/sscanf (stack-address args -> input). The
 * format position (rcx=arg0 -> printf/scanf; rdx=arg1 -> fprintf/sscanf) picks the variant.
 * Naming-only, runs before resolve_symbols so all call sites use the name. DS_NO_FMTFN. */
/* Is `addr` (VA or RVA) the ENTRY of a recovered function? e->funcs is sorted by
 * rva, so this is a binary search. Used to tell a tail call from a local jump. */
static bool func_at_rva(const ds_engine* e, uint64_t addr) {
    uint64_t rva = (addr >= e->base) ? addr - e->base : addr;
    size_t lo = 0, hi = e->func_len;
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) >> 1);
        if (e->funcs[mid].rva < rva) lo = mid + 1; else hi = mid;
    }
    return lo < e->func_len && e->funcs[lo].rva == rva;
}

extern "C" void ds_engine_scan_format_fns(ds_engine* e) {
    if (std::getenv("DS_NO_FMTFN")) return;
    if (!e || e->arch != DS_ARCH_X64 || !e->image || !e->insn_len) return;
    struct Agg { int sites = 0; int after_sites = 0, before_sites = 0; int pos[4] = {0,0,0,0}; bool has_s = false; };
    std::map<uint64_t, Agg> agg;
    auto argidx = [](const std::string& r) -> int {
        return r=="rcx"?0 : r=="rdx"?1 : r=="r8"?2 : r=="r9"?3 : -1; };
    for (size_t i = 0; i < e->insn_len; ++i) {
        const ds_insn* call = &e->insns[i];
        if (!call->ref_target) continue;
        /* A TAIL CALL counts as a call site. `return printf(fmt, x);` compiles under
         * /O2 to `lea rcx,[fmt]; ... ; jmp printf` — a DS_REF_JMP, not a DS_REF_CALL.
         * Only counting real calls meant printf's sites were invisible whenever the
         * caller returned the result directly, which is the common shape for thin
         * wrappers: measured on _qa/fixtures/iotest, printf aggregated ZERO sites
         * while scanf (whose callers use the value, so it stays a real call) got
         * two. That is the whole of "printf is sometimes detected and sometimes
         * not" — it tracked the caller's return shape, not printf.
         * A jmp is only a tail call when it lands on a function ENTRY; an
         * intra-function jump is control flow and must not count. */
        bool is_call = (call->ref_type == DS_REF_CALL);
        bool is_tail = (call->ref_type == DS_REF_JMP) && func_at_rva(e, call->ref_target);
        if (!is_call && !is_tail) continue;
        uint64_t F = (call->ref_target >= e->base) ? call->ref_target - e->base : call->ref_target;
        int fmt_pos = -1; unsigned stack_mask = 0; bool fmt_has_s = false;
        for (size_t b = i; b-- > 0 && i - b <= 14; ) {   /* scan the arg-setup window before the call */
            const ds_insn* in = &e->insns[b];
            if (!std::strcmp(in->mnemonic,"call") || !std::strcmp(in->mnemonic,"ret") ||
                in->mnemonic[0] == 'j') break;           /* prior call/branch = arg-setup boundary */
            int ai = argidx(first_reg_tok(in->operands));
            if (ai < 0) continue;
            bool hs = false;
            if (!std::strcmp(in->mnemonic,"lea") && in->ref_type==DS_REF_DATA && in->ref_target &&
                looks_like_fmt_string(e, in->ref_target, &hs)) {
                if (fmt_pos < 0) { fmt_pos = ai; fmt_has_s = hs; }
            } else if (!std::strcmp(in->mnemonic,"lea") &&
                       (std::strstr(in->operands,"[rsp") || std::strstr(in->operands,"[rbp"))) {
                stack_mask |= (1u << ai);                /* this arg reg = a stack address */
            }
        }
        if (fmt_pos >= 0) {
            Agg& a = agg[F]; a.sites++; a.pos[fmt_pos]++;
            /* a stack address AFTER the format = an output target being written (scanf);
             * BEFORE the format = a destination buffer (sprintf). */
            for (int k = fmt_pos + 1; k < 4; ++k) if (stack_mask & (1u << k)) { a.after_sites++; break; }
            for (int k = 0; k < fmt_pos; ++k)     if (stack_mask & (1u << k)) { a.before_sites++; break; }
            if (fmt_has_s) a.has_s = true;
        }
    }
    for (auto& kv : agg) {
        const Agg& a = kv.second;
        /* >=2 format-string sites. This was 3, which is why printf came out named
         * on some binaries and left as fun_XXXX on others: the threshold is a
         * property of how often the BINARY happens to call it, not of how sure we
         * are that it IS printf. A callee handed a `%`-conversion literal in arg0
         * from two independent sites, with the argument-position shape below
         * deciding which family member it is, is already a confident call — the
         * evidence is the format string, and a second site only rules out a
         * one-off coincidence. Note this pass is a FALLBACK: in the app, FLIRT
         * usually names a statically-linked CRT printf first (the batch dump tool
         * does not run FLIRT, which is why it shows up more often there). */
        if (std::getenv("DS_DBG_FMTFN"))
            fprintf(stderr, "[fmtfn] F=%#llx sites=%d pos=[%d,%d,%d,%d] after=%d before=%d has_s=%d\n",
                    (unsigned long long)kv.first, a.sites, a.pos[0], a.pos[1], a.pos[2], a.pos[3],
                    a.after_sites, a.before_sites, (int)a.has_s);
        if (a.sites < 2) continue;
        uint64_t F = kv.first;
        bool named = false;                              /* only name still-anonymous funcs */
        for (size_t i = 0; i < e->symbol_len; ++i)
            if (e->symbols[i].rva == F && e->symbols[i].name[0]) { named = true; break; }
        if (named) continue;
        int pos = 0; for (int k = 1; k < 4; ++k) if (a.pos[k] > a.pos[pos]) pos = k;
        /* scanf: a stack-ADDRESS arg AFTER the format (an out-var written through) at most sites
         * AND no %s (a %s address is just a printf string buffer -> not input). sprintf: a stack
         * buffer BEFORE the format (the destination). Else printf (pos0) / fprintf (pos>=1). */
        bool input   = !a.has_s && a.after_sites * 2 >= a.sites;
        bool tobuf   = !input && a.before_sites * 2 >= a.sites;
        const char* nm = input  ? (pos == 0 ? "scanf" : "sscanf")
                       : tobuf  ? "sprintf"
                       : (pos == 0 ? "printf" : "fprintf");
        char buf[48];
        if (name_in_use(e, nm)) std::snprintf(buf, sizeof buf, "%s_%llx", nm, (unsigned long long)F);
        else                    std::snprintf(buf, sizeof buf, "%s", nm);
        ds_engine_add_symbol(e, F, buf);
    }
}
