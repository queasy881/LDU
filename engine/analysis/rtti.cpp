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

/* ".?AVFoo@ns@@" -> "ns::Foo". The decorated form lists qualifiers innermost
 * first, so reverse and join with "::". Tag at name[3]: V=class U=struct W=enum
 * T=union. Empty if the shape is unexpected. */
std::string demangle(const std::string& dec) {
    if (dec.rfind(".?A", 0) != 0 || dec.size() < 5) return "";
    std::string body = dec.substr(4);            /* after ".?A" + tag char */
    size_t at = body.rfind("@@");
    if (at != std::string::npos) body = body.substr(0, at);
    std::vector<std::string> parts; std::string cur;
    for (char c : body) { if (c == '@') { parts.push_back(cur); cur.clear(); } else cur.push_back(c); }
    parts.push_back(cur);
    std::string out;
    for (size_t i = parts.size(); i-- > 0; ) {
        if (parts[i].empty()) continue;
        if (!out.empty()) out += "::";
        out += parts[i];
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

/* minimal Itanium demangler for the _ZTS payload (a <class-type> mangling):
 *   simple  <len><name>            -> "name"
 *   nested  N <len><name> ... E    -> "a::b::c"
 * Only <source-name> components (decimal length + identifier bytes). Rejects templates/
 * operators/substitutions (returns "") so we never mis-name. Must consume the whole string. */
std::string itanium_demangle(const std::string& s) {
    size_t i = 0; bool nested = false;
    if (i < s.size() && s[i] == 'N') { nested = true; ++i; }
    std::vector<std::string> parts;
    while (i < s.size()) {
        if (nested && s[i] == 'E') { ++i; break; }
        if (s[i] < '1' || s[i] > '9') return "";
        size_t len = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') { len = len * 10 + (size_t)(s[i] - '0'); ++i; }
        if (len == 0 || i + len > s.size()) return "";
        std::string comp = s.substr(i, len);
        for (char c : comp)
            if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_')) return "";
        parts.push_back(comp); i += len;
        if (!nested) break;               /* simple form is exactly one component */
    }
    if (i != s.size() || parts.empty()) return "";
    std::string out;
    for (size_t k = 0; k < parts.size(); ++k) { if (k) out += "::"; out += parts[k]; }
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
            std::string cls = c_safe(itanium_demangle(str));
            if (cls.empty()) continue;

            std::vector<uint64_t> ti_name_slots; find_refs(e->base + p, ti_name_slots);
            for (uint64_t ns : ti_name_slots) {               /* _ZTI whose +8 name-slot -> this string */
                if (ns < 8) continue;
                uint64_t ti_rva = ns - 8;
                uint64_t tivt;                                /* typeinfo[0] = its own vtable ptr. It is often
                 * IMPORTED (__class_type_info's vtable lives in libstdc++), so it may be an IAT/thunk
                 * pointer rather than in-image — only require a readable, non-null qword here. The real
                 * filter is the string<-ti<-vtable double back-link plus the exec-vfunc check below. */
                if (!read_u64(e, ti_rva, tivt) || tivt == 0) continue;

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
                    if (sotop == 0 && !already_seeded(e, vfun_rva)) {   /* name the vtable at &slot[2] */
                        char vt[112]; std::snprintf(vt, sizeof vt, "%s__vftable", cls.c_str());
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

} // namespace

extern "C" void ds_engine_scan_rtti(ds_engine* e) {
    static const bool off = std::getenv("DS_NO_RTTI") != nullptr;
    if (off || !e || e->arch != DS_ARCH_X64 || !e->image) return;

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
            std::string cls = c_safe(demangle(dec));
            if (cls.empty()) continue;
            /* Name the VTABLE itself (at `pos`, where slot 0 is — this is exactly the
             * address an object stores at +0). So a ctor's `*obj = <vtable>` renders as
             * `obj->__vftbl = &<Class>__vftable`, and struct recovery can recognize that a
             * struct whose field_0 holds a `*__vftable` address IS this class. Only for the
             * primary (offc==0) vtable so the tag is the class name. */
            if (offc == 0 && !already_seeded(e, pos)) {
                char vt[112]; std::snprintf(vt, sizeof vt, "%s__vftable", cls.c_str());
                ds_engine_add_symbol(e, pos, vt);
            }
            for (int i = 0; i < 4096; ++i) {
                uint64_t v;
                if (!read_u64(e, pos + 8 * (uint64_t)i, v) || v < e->base) break;
                uint64_t fn = v - e->base;
                if (!ds_rva_is_exec(e, fn)) break;   /* next vtable's COL-qword -> data: natural stop */
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
}
