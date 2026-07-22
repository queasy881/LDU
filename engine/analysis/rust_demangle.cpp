/*
 * rust_demangle.cpp — from-scratch Rust symbol demangler.
 *
 * Two schemes coexist in the wild and both show up in a single Rust binary's
 * PDB / symbol table:
 *
 *   legacy  `_ZN3foo3barE`         Itanium-flavoured, length-prefixed idents,
 *           `_ZN..17h<16hex>E`     with a trailing `17h<hash>` disambiguator and
 *                                  `$XX$` / `..` punctuation escapes.
 *   v0      `_RNvNtC..`            RFC 2603: a typed, back-referenced grammar
 *                                  (paths, generics, impls, dyn, fn-ptrs).
 *
 * We implement legacy fully and a robust subset of v0 (every construct that
 * appears in real function symbols: crate roots, nested paths, inherent/trait
 * impls, generic args, back-refs, and the type grammar they nest). Anything we
 * cannot parse cleanly yields "" so the caller keeps the raw name rather than
 * emitting garbage.
 */
#include "rust_demangle.h"
#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

namespace {

/* ---- legacy `_ZN...E` ----------------------------------------------------- */

bool is_hex16(const std::string& s) {
    if (s.size() != 17 || s[0] != 'h') return false;
    for (size_t i = 1; i < 17; ++i)
        if (!std::isxdigit((unsigned char)s[i])) return false;
    return true;
}

/* decode one legacy path component: `$LT$`->'<', `..`->"::", `$u7e$`->'~', etc. */
std::string legacy_decode(const std::string& in) {
    std::string s = in;
    /* a component that would start with a non-ident char is prefixed with '_' */
    if (s.size() >= 2 && s[0] == '_' && s[1] == '$') s.erase(0, 1);
    std::string out;
    for (size_t i = 0; i < s.size();) {
        if (s[i] == '$') {
            size_t e = s.find('$', i + 1);
            if (e == std::string::npos) { out += s[i++]; continue; }
            std::string code = s.substr(i + 1, e - i - 1);
            if (code == "SP") out += '@';
            else if (code == "BP") out += '*';
            else if (code == "RF") out += '&';
            else if (code == "LT") out += '<';
            else if (code == "GT") out += '>';
            else if (code == "LP") out += '(';
            else if (code == "RP") out += ')';
            else if (code == "C") out += ',';
            else if (!code.empty() && code[0] == 'u') {
                /* $u7e$ style: hex codepoint */
                long cp = std::strtol(code.c_str() + 1, nullptr, 16);
                if (cp > 0 && cp < 0x80) out += (char)cp;
                else out += '?';
            } else {
                out += s.substr(i, e - i + 1);  /* unknown: keep literal */
            }
            i = e + 1;
        } else if (s[i] == '.' && i + 1 < s.size() && s[i + 1] == '.') {
            out += "::"; i += 2;
        } else {
            out += s[i++];
        }
    }
    return out;
}

std::string demangle_legacy(const std::string& sym) {
    size_t i;
    if (sym.compare(0, 3, "_ZN") == 0) i = 3;
    else if (sym.compare(0, 2, "ZN") == 0) i = 2;
    else return "";
    std::vector<std::string> parts;
    while (i < sym.size() && std::isdigit((unsigned char)sym[i])) {
        size_t len = 0;
        while (i < sym.size() && std::isdigit((unsigned char)sym[i]))
            len = len * 10 + (sym[i++] - '0');
        if (len == 0 || i + len > sym.size()) return "";
        parts.push_back(sym.substr(i, len));
        i += len;
    }
    if (parts.empty()) return "";
    /* the trailing `17h<16hex>` component is the codegen-unit hash; drop it */
    bool had_hash = is_hex16(parts.back());
    if (had_hash) parts.pop_back();
    else return "";  /* no Rust hash -> not a Rust legacy symbol (leave C++ alone) */
    if (parts.empty()) return "";
    std::string out;
    for (auto& p : parts) {
        if (!out.empty()) out += "::";
        out += legacy_decode(p);
    }
    return out;
}

/* ---- v0 `_R...` (RFC 2603) ------------------------------------------------ */

struct V0 {
    const std::string& s;   /* the mangling with the `_R` prefix stripped */
    size_t pos = 0;
    bool err = false;
    int depth = 0;

    explicit V0(const std::string& in) : s(in) {}

    char peek() const { return pos < s.size() ? s[pos] : '\0'; }
    char take() { return pos < s.size() ? s[pos++] : (err = true, '\0'); }
    bool eat(char c) { if (peek() == c) { ++pos; return true; } return false; }

    /* base-62: {0-9a-zA-Z} '_' ; empty => 0, else value+1 */
    uint64_t base62() {
        if (eat('_')) return 0;
        uint64_t v = 0;
        while (pos < s.size()) {
            char c = s[pos];
            uint64_t d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'z') d = 10 + (c - 'a');
            else if (c >= 'A' && c <= 'Z') d = 36 + (c - 'A');
            else break;
            v = v * 62 + d; ++pos;
        }
        if (!eat('_')) { err = true; return 0; }
        return v + 1;
    }

    void disambiguator() { if (peek() == 's') { ++pos; base62(); } }

    uint64_t decimal() {
        if (!std::isdigit((unsigned char)peek())) { err = true; return 0; }
        /* v0 lengths are canonical: no leading zeros, so a bare "0" is a
         * length-0 (empty) identifier — e.g. a `{{closure}}` whose "0" would
         * otherwise greedily merge with the next component's length prefix. */
        if (peek() == '0') { ++pos; return 0; }
        uint64_t v = 0;
        while (std::isdigit((unsigned char)peek())) v = v * 10 + (take() - '0');
        return v;
    }

    std::string ident() {
        bool puny = eat('u');
        uint64_t len = decimal();
        eat('_');                       /* optional separator */
        if (err || pos + len > s.size()) { err = true; return ""; }
        std::string raw = s.substr(pos, len);
        pos += len;
        if (puny) return raw + "{punycode}";   /* rare; keep raw + marker */
        return raw;
    }

    const char* basic_type(char c) {
        switch (c) {
            case 'a': return "i8";   case 'b': return "bool"; case 'c': return "char";
            case 'd': return "f64";  case 'e': return "str";  case 'f': return "f32";
            case 'h': return "u8";   case 'i': return "isize";case 'j': return "usize";
            case 'l': return "i32";  case 'm': return "u32";  case 'n': return "i128";
            case 'o': return "u128"; case 's': return "i16";  case 't': return "u16";
            case 'u': return "()";   case 'x': return "i64";  case 'y': return "u64";
            case 'z': return "!";    case 'p': return "_";    case 'v': return "...";
            default:  return nullptr;
        }
    }

    void backref(void (V0::*fn)(std::string&), std::string& out) {
        uint64_t off = base62();
        if (err || off >= pos) { err = true; return; }
        size_t save = pos; pos = (size_t)off;
        (this->*fn)(out);
        pos = save;
    }

    void path(std::string& out) {
        if (err || ++depth > 200) { err = true; return; }
        char t = take();
        switch (t) {
            case 'C': {                       /* crate-root */
                disambiguator();
                out += ident();
                break;
            }
            case 'N': {                       /* nested: ns path ident */
                take();                       /* namespace char */
                std::string base; path(base);
                disambiguator();
                std::string id = ident();
                out += base;
                if (!id.empty()) { out += "::"; out += id; }
                break;
            }
            case 'M': {                       /* inherent impl: impl-path type */
                disambiguator();
                std::string junk; path(junk);
                std::string ty; type(ty);
                out += "<" + ty + ">";
                break;
            }
            case 'X': {                       /* trait impl: impl-path type trait */
                disambiguator();
                std::string junk; path(junk);
                std::string ty, tr; type(ty); path(tr);
                out += "<" + ty + " as " + tr + ">";
                break;
            }
            case 'Y': {                       /* trait def: type trait */
                std::string ty, tr; type(ty); path(tr);
                out += "<" + ty + " as " + tr + ">";
                break;
            }
            case 'I': {                       /* generic: path {arg} E */
                std::string base; path(base);
                out += base + "::<";
                bool first = true;
                while (peek() != 'E' && !err) {
                    std::string a; generic_arg(a);
                    if (!first) out += ", ";
                    out += a; first = false;
                }
                eat('E');
                out += ">";
                break;
            }
            case 'B': backref(&V0::path, out); break;
            default:  err = true; break;
        }
        --depth;
    }

    void generic_arg(std::string& out) {
        char c = peek();
        if (c == 'L') { ++pos; base62(); out += "'_"; }
        else if (c == 'K') { ++pos; constant(out); }
        else type(out);
    }

    void constant(std::string& out) {
        if (peek() == 'B') { ++pos; backref(&V0::constant, out); return; }
        std::string ty; type(ty);
        if (eat('p')) { out += "_"; return; }
        bool neg = eat('n');
        std::string val;
        while (std::isxdigit((unsigned char)peek())) val += take();
        eat('_');
        out += (neg ? "-" : "") + (val.empty() ? std::string("_") : val);
    }

    void type(std::string& out) {
        if (err || ++depth > 200) { err = true; return; }
        char c = peek();
        const char* bt = basic_type(c);
        if (bt && c != 'B') {                 /* basic types are lowercase; paths upper */
            /* only treat as basic when it is not the start of a path/ctor */
            ++pos; out += bt; --depth; return;
        }
        switch (c) {
            case 'A': { ++pos; std::string e, n; type(e); constant(n); out += "[" + e + "; " + n + "]"; break; }
            case 'S': { ++pos; std::string e; type(e); out += "[" + e + "]"; break; }
            case 'T': { ++pos; out += "("; bool f = true;
                        while (peek() != 'E' && !err) { std::string e; type(e); if (!f) out += ", "; out += e; f = false; }
                        eat('E'); out += ")"; break; }
            case 'R': { ++pos; if (peek() == 'L') { ++pos; base62(); } std::string e; type(e); out += "&" + e; break; }
            case 'Q': { ++pos; if (peek() == 'L') { ++pos; base62(); } std::string e; type(e); out += "&mut " + e; break; }
            case 'P': { ++pos; std::string e; type(e); out += "*const " + e; break; }
            case 'O': { ++pos; std::string e; type(e); out += "*mut " + e; break; }
            case 'F': { ++pos; fn_sig(out); break; }
            case 'D': { ++pos; dyn_bounds(out); if (peek() == 'L') { ++pos; base62(); } break; }
            case 'B': ++pos; backref(&V0::type, out); break;   /* consume 'B' before the back-ref index */
            default:  path(out); break;       /* uppercase C/N/M/X/Y/I -> path */
        }
        --depth;
    }

    void fn_sig(std::string& out) {
        if (peek() == 'G') { ++pos; base62(); }   /* binder */
        eat('U');                                 /* unsafe */
        if (eat('K')) { if (!eat('C')) ident(); } /* extern "abi" */
        out += "fn(";
        bool f = true;
        while (peek() != 'E' && !err) { std::string e; type(e); if (!f) out += ", "; out += e; f = false; }
        eat('E');
        std::string ret; type(ret);
        out += ") -> " + ret;
    }

    void dyn_bounds(std::string& out) {
        if (peek() == 'G') { ++pos; base62(); }
        out += "dyn ";
        bool f = true;
        while (peek() != 'E' && !err) {
            std::string tr; path(tr);
            while (peek() == 'p') { ++pos; ident(); std::string t; type(t); }  /* assoc bindings */
            if (!f) out += " + ";
            out += tr; f = false;
        }
        eat('E');
    }
};

std::string demangle_v0(const std::string& sym) {
    if (sym.compare(0, 2, "_R") != 0) return "";
    std::string body = sym.substr(2);
    size_t dot = body.find('.');                  /* strip .llvm.NN / .cold vendor suffix */
    if (dot != std::string::npos) body = body.substr(0, dot);
    V0 p(body);
    std::string out;
    p.path(out);
    if (p.err || out.empty()) return "";
    return out;
}

}  // namespace

std::string ds_rust_demangle(const std::string& mangled) {
    if (mangled.size() < 3) return "";
    if (mangled[0] == '_' && mangled[1] == 'R') return demangle_v0(mangled);
    if (mangled.compare(0, 3, "_ZN") == 0 || mangled.compare(0, 2, "ZN") == 0)
        return demangle_legacy(mangled);
    return "";
}
