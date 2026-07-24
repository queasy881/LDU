/*
 * annotations.cpp — persistent user annotations (renames/comments that survive
 * re-analysis), backed by a JSON sidecar.
 *
 * ---- WHY NOT KEY ON THE RVA -----------------------------------------------
 * An rva is not an identity: adding one line to an unrelated function shifts every
 * later function's rva and every annotation would silently land on the WRONG code.
 * So the primary key is a hash of what the function IS, with the rva kept only as a
 * fallback for the case where the hash is unavailable.
 *
 * ---- WHY THE HASH IS OVER A *MASKED* INSTRUCTION STREAM --------------------
 * Hashing the raw function bytes would be no more stable than the rva it replaces:
 * call/jmp displacements and RIP-relative data references are encoded as offsets that
 * move on ANY rebuild, so an untouched function hashes differently. The decoder
 * already flags exactly those operands (ds_insn.ref_type/ref_target), so we fold in
 * the mnemonic + length + a ref-kind tag for referencing instructions, and the raw
 * bytes for everything else. That masks the volatile fields and keeps the real shape.
 *
 * ---- IDENTITY RULES (ds_anno_resolve; every decline is deliberate) ---------
 *   (1) hash match, only when the hash picks out EXACTLY ONE current function. Two
 *       identical small thunks hash the same; renaming an arbitrary one of them is
 *       the "confident lie" the house rules forbid, so an ambiguous hash declines
 *       and drops to the rva.
 *   (2) rva match, but DECLINED when both hashes are known and differ — that rva
 *       holds different code now, and the old name would misdescribe it.
 * The answer is published in ds_anno.bound so consumers never re-derive it.
 *
 * ---- FILE FORMAT (version 1) ----------------------------------------------
 *   {
 *     "version": 1,
 *     "binary": "classtest.dll",        // provenance only, never matched on
 *     "image_size": 45056,              // provenance only
 *     "functions": [
 *       { "hash": "0x9ae16a3b2f90404f", // primary key; "0x0"/absent = unavailable
 *         "rva":  "0x1080",             // fallback key
 *         "name": "parse_header",       // optional rename
 *         "comment": "returns -1 on bad magic",   // optional, free text
 *         "vars": [ { "from": "v3", "to": "cursor" } ] }   // optional
 *     ]
 *   }
 * Unknown keys are skipped, so a newer writer degrades rather than failing. Numbers
 * are accepted anywhere a hex string is, for hand-written files.
 *
 * Gated by DS_NO_ANNO (kill switch); DS_ANNO_FILE=<path> auto-loads a sidecar.
 */
#include "disasm.h"
#include "engine_internal.h"
#include "vec.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace {

bool anno_disabled() {
    static const bool off = std::getenv("DS_NO_ANNO") != nullptr;
    return off;
}

/* ---- stable identity ----------------------------------------------------- */

/* fnv1a64 over the masked instruction stream. Never returns 0 on success: 0 is
 * reserved for "no identity available" so callers can test it. */
uint64_t hash_func(const ds_engine* e, const ds_func* f) {
    if (!e || !f || f->size == 0) return 0;
    uint64_t h = 1469598103934665603ULL;
    auto mix = [&h](uint8_t b) { h ^= (uint64_t)b; h *= 1099511628211ULL; };

    size_t i = ds_insn_lower_bound(e, f->rva);
    if (i == SIZE_MAX || i >= e->insn_len || e->insns[i].rva != f->rva) return 0;
    const uint64_t end = f->rva + f->size;
    size_t n = 0;
    for (; i < e->insn_len && e->insns[i].rva < end; ++i, ++n) {
        const ds_insn* in = &e->insns[i];
        for (const char* m = in->mnemonic; *m; ++m) mix((uint8_t)*m);
        mix(0);
        mix(in->size);
        if (in->ref_type != DS_REF_NONE) {
            /* volatile operand: keep the KIND of reference (real shape), drop the
             * target/displacement bytes (they move on every rebuild). */
            mix(0xFE);
            mix(in->ref_type);
        } else {
            for (uint8_t k = 0; k < in->size && k < sizeof(in->bytes); ++k)
                mix(in->bytes[k]);
        }
    }
    if (n == 0) return 0;
    return h ? h : 1;
}

/* ---- a minimal JSON reader for our own restricted subset ------------------ */

struct JVal {
    enum T { NUL, BOOL, NUM, STR, ARR, OBJ } t = NUL;
    bool        b = false;
    double      n = 0;
    std::string s;
    std::vector<JVal> arr;
    std::vector<std::pair<std::string, JVal> > obj;

    const JVal* get(const char* k) const {
        if (t != OBJ) return NULL;
        for (size_t i = 0; i < obj.size(); ++i)
            if (obj[i].first == k) return &obj[i].second;
        return NULL;
    }
    /* a hex string ("0x1f") or a plain number, both -> u64. `dflt` when absent. */
    uint64_t u64(const char* k, uint64_t dflt = 0) const {
        const JVal* v = get(k);
        if (!v) return dflt;
        if (v->t == NUM) return (uint64_t)v->n;
        if (v->t == STR) return (uint64_t)std::strtoull(v->s.c_str(), NULL, 0);
        return dflt;
    }
    std::string str(const char* k) const {
        const JVal* v = get(k);
        return (v && v->t == STR) ? v->s : std::string();
    }
};

struct JParser {
    const char* p;
    const char* end;
    bool ok = true;
    int  depth = 0;

    JParser(const char* b, const char* e) : p(b), end(e) {}

    void ws() {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p;
    }
    bool eat(char c) { ws(); if (p < end && *p == c) { ++p; return true; } return false; }

    bool hex4(unsigned& out) {
        if (end - p < 4) return false;
        out = 0;
        for (int i = 0; i < 4; ++i) {
            char c = p[i];
            unsigned d;
            if (c >= '0' && c <= '9') d = (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') d = (unsigned)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') d = (unsigned)(c - 'A' + 10);
            else return false;
            out = (out << 4) | d;
        }
        p += 4;
        return true;
    }

    bool str(std::string& out) {
        if (!eat('"')) return false;
        out.clear();
        while (p < end) {
            char c = *p++;
            if (c == '"') return true;
            if (c != '\\') { out.push_back(c); continue; }
            if (p >= end) break;
            char x = *p++;
            switch (x) {
                case '"':  out.push_back('"');  break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/');  break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                case 'u': {
                    /* Our fields are identifiers and prose that end up in C source; a
                     * non-ASCII escape has no safe rendering here, so fold it to '?'
                     * rather than inventing bytes. */
                    unsigned cp;
                    if (!hex4(cp)) return false;
                    out.push_back(cp < 0x80 ? (char)cp : '?');
                    break;
                }
                default: return false;
            }
        }
        return false;
    }

    bool value(JVal& v) {
        if (++depth > 32) return false;   /* refuse to blow the C stack on nesting */
        bool r = value_inner(v);
        --depth;
        return r;
    }

    bool value_inner(JVal& v) {
        ws();
        if (p >= end) return false;
        char c = *p;
        if (c == '"') { v.t = JVal::STR; return str(v.s); }
        if (c == '{') {
            ++p; v.t = JVal::OBJ;
            ws();
            if (eat('}')) return true;
            for (;;) {
                std::string k;
                if (!str(k)) return false;
                if (!eat(':')) return false;
                JVal child;
                if (!value(child)) return false;
                v.obj.push_back(std::make_pair(k, child));
                if (eat(',')) continue;
                return eat('}');
            }
        }
        if (c == '[') {
            ++p; v.t = JVal::ARR;
            ws();
            if (eat(']')) return true;
            for (;;) {
                JVal child;
                if (!value(child)) return false;
                v.arr.push_back(child);
                if (eat(',')) continue;
                return eat(']');
            }
        }
        if (c == 't' || c == 'f' || c == 'n') {
            const char* lit = (c == 't') ? "true" : (c == 'f' ? "false" : "null");
            size_t n = std::strlen(lit);
            if ((size_t)(end - p) < n || std::strncmp(p, lit, n) != 0) return false;
            p += n;
            v.t = (c == 'n') ? JVal::NUL : JVal::BOOL;
            v.b = (c == 't');
            return true;
        }
        if (c == '-' || (c >= '0' && c <= '9')) {
            char* fin = NULL;
            v.t = JVal::NUM;
            v.n = std::strtod(p, &fin);
            if (fin == p) return false;
            p = fin;
            return true;
        }
        return false;
    }
};

/* ---- JSON writing -------------------------------------------------------- */

std::string jstr(const char* s) {
    std::string o = "\"";
    for (const unsigned char* q = (const unsigned char*)s; *q; ++q) {
        switch (*q) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (*q < 0x20) { char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", *q); o += b; }
                else o.push_back((char)*q);
        }
    }
    o += "\"";
    return o;
}

std::string jhex(uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof(b), "\"0x%llx\"", (unsigned long long)v);
    return b;
}

/* ---- store mutation ------------------------------------------------------ */

ds_anno* anno_upsert(ds_engine* e, uint64_t rva) {
    for (size_t i = 0; i < e->anno_len; ++i)
        if (e->annos[i].rva == rva) return &e->annos[i];
    if (!ds_vec_reserve((void**)&e->annos, &e->anno_cap, e->anno_len + 1, sizeof(ds_anno)))
        return NULL;
    ds_anno* a = &e->annos[e->anno_len++];
    std::memset(a, 0, sizeof(*a));
    a->rva = rva;
    a->bound = DS_ANNO_UNBOUND;
    return a;
}

const ds_func* func_at(const ds_engine* e, uint64_t rva) {
    for (size_t i = 0; i < e->func_len; ++i)
        if (e->funcs[i].rva == rva) return &e->funcs[i];
    return NULL;
}

} // namespace

/* ---- shared helpers ------------------------------------------------------ */

extern "C" uint64_t ds_anno_func_hash(const ds_engine* e, const ds_func* f) {
    return hash_func(e, f);
}

extern "C" void ds_anno_resolve(ds_engine* e) {
    if (!e || anno_disabled()) return;
    if (e->anno_len == 0 && e->anno_var_len == 0) return;   /* the common case: free */

    /* hash every current function once, and count each hash so an ambiguous one
     * (identical thunks) can be recognized and declined. */
    std::vector<uint64_t> fh(e->func_len, 0);
    std::map<uint64_t, int> hcount;
    std::map<uint64_t, size_t> hfirst;
    for (size_t i = 0; i < e->func_len; ++i) {
        fh[i] = hash_func(e, &e->funcs[i]);
        if (!fh[i]) continue;
        if (hcount[fh[i]]++ == 0) hfirst[fh[i]] = i;
    }

    /* Bind ONE identity (hash, rva) to a current function rva, or DS_ANNO_UNBOUND. */
    auto bind = [&](uint64_t hash, uint64_t rva) -> uint64_t {
        if (hash) {
            std::map<uint64_t, int>::iterator c = hcount.find(hash);
            if (c != hcount.end() && c->second == 1)
                return e->funcs[hfirst[hash]].rva;
        }
        for (size_t i = 0; i < e->func_len; ++i) {
            if (e->funcs[i].rva != rva) continue;
            /* both identities known and different -> different code lives here now */
            if (hash && fh[i] && hash != fh[i]) return DS_ANNO_UNBOUND;
            return rva;
        }
        return DS_ANNO_UNBOUND;
    };

    /* A function takes at most one annotation: two sidecar entries resolving to the
     * same function is ambiguous, so the first (file order) wins deterministically
     * rather than letting an arbitrary last-writer decide the name. */
    std::map<uint64_t, size_t> owner;
    for (size_t i = 0; i < e->anno_len; ++i) {
        ds_anno* a = &e->annos[i];
        a->bound = bind(a->hash, a->rva);
        if (a->bound == DS_ANNO_UNBOUND) continue;
        if (owner.count(a->bound)) { a->bound = DS_ANNO_UNBOUND; continue; }
        owner[a->bound] = i;
    }
    /* vars are naturally many-per-function, so no owner check here */
    for (size_t i = 0; i < e->anno_var_len; ++i) {
        ds_anno_var* v = &e->anno_vars[i];
        v->bound = bind(v->hash, v->rva);
    }
}

extern "C" const ds_anno* ds_anno_for_func(const ds_engine* e, uint64_t rva) {
    if (!e || anno_disabled()) return NULL;
    for (size_t i = 0; i < e->anno_len; ++i)
        if (e->annos[i].bound == rva) return &e->annos[i];
    return NULL;
}

/* ---- public API ---------------------------------------------------------- */

extern "C" void ds_engine_set_func_annotation(ds_engine* e, uint64_t rva,
                                              const char* name, const char* comment) {
    if (!e) return;
    ds_anno* a = anno_upsert(e, rva);
    if (!a) return;
    const ds_func* f = func_at(e, rva);
    if (f) a->hash = hash_func(e, f);   /* capture the identity while we can see it */
    if (name && name[0])       ds_strlcpy(a->name, name, sizeof(a->name));
    if (comment && comment[0]) ds_strlcpy(a->comment, comment, sizeof(a->comment));
    a->bound = DS_ANNO_UNBOUND;         /* re-derived by ds_anno_resolve */
}

/* Guards the anno_vars VECTOR against a concurrent decompile.
 *
 * bridge's `unsafe impl Sync for Engine` is justified by "ds_decompile never
 * mutates the engine, so many threads may hold &Engine and decompile at once".
 * Interactive retyping is the first thing that writes to a live engine, and the
 * write can REALLOC the vector while another thread is reading it — so every
 * access goes through this lock, and readers take a COPY rather than a pointer
 * into the vector. Once per decompile, so the cost is nothing. */
static std::mutex& anno_var_mtx() { static std::mutex m; return m; }

/* Copy this function's variable TYPE overrides out under the lock. Returns the
 * number written (never more than `max`). */
extern "C" size_t ds_engine_get_var_types(ds_engine* e, uint64_t rva,
                                          ds_var_type* out, size_t max) {
    if (!e || anno_disabled()) return 0;
    std::lock_guard<std::mutex> lk(anno_var_mtx());
    size_t n = 0;
    /* `out == NULL` is the COUNT query — it must not be bounded by `max`, or the
     * usual count-then-fetch call (max = 0) always answers "none". */
    for (size_t i = 0; i < e->anno_var_len && (!out || n < max); ++i) {
        const ds_anno_var& v = e->anno_vars[i];
        if (v.bound != rva || !v.type[0] || !v.from[0]) continue;
        if (out) {
            ds_strlcpy(out[n].var,  v.from, sizeof(out[n].var));
            ds_strlcpy(out[n].type, v.type, sizeof(out[n].type));
        }
        ++n;
    }
    return n;
}

/* Find-or-create the annotation record for one display variable of one function.
 * Shared by the rename and the retype setters, which differ only in which field
 * they write. Caller holds anno_var_mtx(). */
static ds_anno_var* anno_var_upsert(ds_engine* e, uint64_t rva, const char* from) {
    uint64_t hash = 0;
    const ds_func* f = func_at(e, rva);
    if (f) hash = hash_func(e, f);

    ds_anno_var* v = NULL;
    for (size_t i = 0; i < e->anno_var_len; ++i)
        if (e->anno_vars[i].rva == rva && std::strcmp(e->anno_vars[i].from, from) == 0)
            v = &e->anno_vars[i];
    if (!v) {
        if (!ds_vec_reserve((void**)&e->anno_vars, &e->anno_var_cap,
                            e->anno_var_len + 1, sizeof(ds_anno_var)))
            return NULL;
        v = &e->anno_vars[e->anno_var_len++];
        std::memset(v, 0, sizeof(*v));
        v->rva = rva;
        ds_strlcpy(v->from, from, sizeof(v->from));
    }
    v->hash = hash;
    /* Bind IMMEDIATELY to the function that is at this rva right now, instead of
     * leaving it UNBOUND for the next ds_anno_resolve. The caller just pointed at
     * this function interactively, so its identity is not in question — and
     * requiring a re-resolve would mean a rename/retype could only take effect
     * after re-running analysis over every function, which is precisely what an
     * interactive edit must not cost. A later load_annotations still re-derives
     * the binding by content hash, so persistence is unaffected. */
    v->bound = f ? rva : DS_ANNO_UNBOUND;
    return v;
}

extern "C" void ds_engine_set_var_annotation(ds_engine* e, uint64_t rva,
                                             const char* from, const char* to) {
    if (!e || !from || !from[0] || !to || !to[0]) return;
    std::lock_guard<std::mutex> lk(anno_var_mtx());
    ds_anno_var* v = anno_var_upsert(e, rva, from);
    if (v) ds_strlcpy(v->to, to, sizeof(v->to));
}

extern "C" void ds_engine_set_var_type(ds_engine* e, uint64_t rva,
                                       const char* var, const char* type) {
    if (!e || !var || !var[0]) return;
    std::lock_guard<std::mutex> lk(anno_var_mtx());
    ds_anno_var* v = anno_var_upsert(e, rva, var);
    if (!v) return;
    /* NULL/"" clears the override and restores the recovered type */
    ds_strlcpy(v->type, type ? type : "", sizeof(v->type));
}

extern "C" int ds_engine_load_annotations(ds_engine* e, const char* path) {
    if (!e || !path) return 1;

    FILE* fp = std::fopen(path, "rb");
    if (!fp) return 1;
    std::string text;
    char buf[4096];
    size_t got;
    while ((got = std::fread(buf, 1, sizeof(buf), fp)) > 0) text.append(buf, got);
    std::fclose(fp);

    JParser jp(text.c_str(), text.c_str() + text.size());
    JVal root;
    if (!jp.value(root) || root.t != JVal::OBJ) return 2;
    if (root.u64("version", 1) != 1) return 2;   /* refuse a format we cannot read */

    const JVal* fns = root.get("functions");
    if (fns && fns->t != JVal::ARR) return 2;

    /* a load REPLACES the store — it is "open this sidecar", not "merge into" */
    e->anno_len = 0;
    e->anno_var_len = 0;
    if (!fns) return 0;

    for (size_t i = 0; i < fns->arr.size(); ++i) {
        const JVal& fn = fns->arr[i];
        if (fn.t != JVal::OBJ) return 2;
        uint64_t rva  = fn.u64("rva");
        uint64_t hash = fn.u64("hash");
        std::string nm = fn.str("name"), cm = fn.str("comment");

        if (!nm.empty() || !cm.empty()) {
            ds_anno* a = anno_upsert(e, rva);
            if (!a) return 1;
            a->hash = hash;
            a->bound = DS_ANNO_UNBOUND;
            if (!nm.empty()) ds_strlcpy(a->name, nm.c_str(), sizeof(a->name));
            if (!cm.empty()) ds_strlcpy(a->comment, cm.c_str(), sizeof(a->comment));
        }

        const JVal* vars = fn.get("vars");
        if (!vars) continue;
        if (vars->t != JVal::ARR) return 2;
        for (size_t k = 0; k < vars->arr.size(); ++k) {
            const JVal& vv = vars->arr[k];
            if (vv.t != JVal::OBJ) return 2;
            std::string from = vv.str("from"), to = vv.str("to"), ty = vv.str("type");
            /* a var entry may carry a rename, a TYPE, or both */
            if (from.empty() || (to.empty() && ty.empty())) continue;
            if (!ds_vec_reserve((void**)&e->anno_vars, &e->anno_var_cap,
                                e->anno_var_len + 1, sizeof(ds_anno_var)))
                return 1;
            ds_anno_var* v = &e->anno_vars[e->anno_var_len++];
            std::memset(v, 0, sizeof(*v));
            v->rva = rva;
            v->hash = hash;
            v->bound = DS_ANNO_UNBOUND;
            ds_strlcpy(v->from, from.c_str(), sizeof(v->from));
            ds_strlcpy(v->to, to.c_str(), sizeof(v->to));
            ds_strlcpy(v->type, ty.c_str(), sizeof(v->type));
        }
    }

    ds_anno_resolve(e);   /* usable immediately when funcs are already recovered */
    return 0;
}

extern "C" int ds_engine_save_annotations(ds_engine* e, const char* path) {
    if (!e || !path) return 1;

    /* group by the identity as RECORDED (hash,rva) so vars land in their function's
     * entry — including vars whose function has no name/comment of its own. */
    struct Key { uint64_t hash, rva; };
    std::vector<Key> keys;
    auto key_index = [&](uint64_t hash, uint64_t rva) -> size_t {
        for (size_t i = 0; i < keys.size(); ++i)
            if (keys[i].hash == hash && keys[i].rva == rva) return i;
        Key k; k.hash = hash; k.rva = rva;
        keys.push_back(k);
        return keys.size() - 1;
    };
    std::map<size_t, size_t> anno_of;                 /* key -> index into e->annos */
    std::map<size_t, std::vector<size_t> > vars_of;   /* key -> indices into anno_vars */
    for (size_t i = 0; i < e->anno_len; ++i) {
        const ds_anno& a = e->annos[i];
        if (!a.name[0] && !a.comment[0]) continue;
        anno_of[key_index(a.hash, a.rva)] = i;
    }
    for (size_t i = 0; i < e->anno_var_len; ++i) {
        const ds_anno_var& v = e->anno_vars[i];
        vars_of[key_index(v.hash, v.rva)].push_back(i);
    }

    std::string o = "{\n  \"version\": 1,\n";
    o += "  \"image_size\": " + std::to_string((unsigned long long)e->image_size) + ",\n";
    o += "  \"functions\": [\n";
    for (size_t k = 0; k < keys.size(); ++k) {
        o += "    { \"hash\": " + jhex(keys[k].hash) + ", \"rva\": " + jhex(keys[k].rva);
        std::map<size_t, size_t>::iterator ai = anno_of.find(k);
        if (ai != anno_of.end()) {
            const ds_anno& a = e->annos[ai->second];
            if (a.name[0])    o += ", \"name\": " + jstr(a.name);
            if (a.comment[0]) o += ", \"comment\": " + jstr(a.comment);
        }
        std::map<size_t, std::vector<size_t> >::iterator vi = vars_of.find(k);
        if (vi != vars_of.end() && !vi->second.empty()) {
            o += ",\n      \"vars\": [ ";
            for (size_t j = 0; j < vi->second.size(); ++j) {
                const ds_anno_var& v = e->anno_vars[vi->second[j]];
                if (j) o += ", ";
                o += "{ \"from\": " + jstr(v.from) + ", \"to\": " + jstr(v.to);
                if (v.type[0]) o += ", \"type\": " + jstr(v.type);
                o += " }";
            }
            o += " ]\n    }";
        } else {
            o += " }";
        }
        o += (k + 1 < keys.size()) ? ",\n" : "\n";
    }
    o += "  ]\n}\n";

    FILE* fp = std::fopen(path, "wb");
    if (!fp) return 1;
    size_t w = std::fwrite(o.data(), 1, o.size(), fp);
    int bad = (w != o.size());
    if (std::fclose(fp) != 0) bad = 1;
    return bad ? 1 : 0;
}
