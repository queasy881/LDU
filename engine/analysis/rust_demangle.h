/*
 * rust_demangle.h — Rust symbol demangler (legacy `_ZN..17h<hash>E` + v0 `_R`).
 *
 * Returns the human-readable path (e.g. "core::fmt::Formatter::pad",
 * "<alloc::string::String>::from_utf16") or "" when `mangled` is not a Rust
 * symbol / fails to parse. Names arriving from the PDB, exports, or FLIRT can
 * be run through this before they are seeded so a Rust binary reads with real
 * module paths instead of `_ZN..` / `_R..` noise.
 */
#ifndef DS_RUST_DEMANGLE_H
#define DS_RUST_DEMANGLE_H
#include <string>
std::string ds_rust_demangle(const std::string& mangled);
#endif
