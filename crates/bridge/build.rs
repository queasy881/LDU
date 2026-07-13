//! Build script for the `bridge` crate.
//!
//! Two jobs:
//!   1. Configure + build the C/C++ engine (`engine/`) as a static library via
//!      CMake, with the capstone backend OFF (so the build is fully offline),
//!      and emit the link directives so `disasmengine` is linked in.
//!   2. Run bindgen against `engine/include/disasm.h` to generate the raw FFI
//!      bindings into `$OUT_DIR/bindings.rs`.
//!
//! IMPORTANT: we pass the engine path as the *relative* "../../engine".
//! Canonicalizing it on Windows yields a `\\?\C:\...` extended-length prefix
//! which CMake chokes on, so we deliberately do NOT canonicalize.

use std::env;
use std::path::{Path, PathBuf};

fn main() {
    // --- locate things relative to the crate manifest -----------------------
    // CARGO_MANIFEST_DIR = crates/bridge ; the engine sits at ../../engine.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let engine_rel = "../../engine";
    let header_rel = "../../engine/include/disasm.h";

    // Absolute paths are only used for include dirs / rerun-if-changed watches
    // (those tolerate the extended-length prefix); the cmake *source* path is
    // kept relative on purpose, per the note above.
    let engine_abs = manifest_dir.join("..").join("..").join("engine");
    let include_abs = engine_abs.join("include");
    let header_abs = include_abs.join("disasm.h");

    // --- 1. build the engine via CMake -------------------------------------
    let mut cfg = cmake::Config::new(engine_rel);
    // capstone is the real disassembly backend; CMake fetches + statically links
    // it (network required at build time, by design).
    cfg.define("DS_USE_CAPSTONE", "ON");
    // Match cargo's CRT linkage: cargo defaults to the dynamic MSVC CRT.
    if cfg!(target_env = "msvc") {
        cfg.static_crt(false);
    }
    let dst = cfg.build();

    // The cmake crate installs into <dst>; the actual archive can live in a few
    // places depending on generator (Ninja vs. Visual Studio multi-config).
    // Emit every plausible search dir so the linker finds libdisasmengine.
    let candidates = [
        dst.join("lib"),
        dst.join("build"),
        dst.join("build").join("Release"),
        dst.join("build").join("Debug"),
        dst.clone(),
    ];
    for c in &candidates {
        if c.exists() {
            println!("cargo:rustc-link-search=native={}", c.display());
        }
    }
    // Always emit the primary install lib dir even if the existence check above
    // raced (it is the canonical location for the Ninja/Makefile generators).
    println!("cargo:rustc-link-search=native={}", dst.join("lib").display());

    println!("cargo:rustc-link-lib=static=disasmengine");

    // capstone is built (statically) somewhere under the CMake tree by
    // FetchContent and is NOT installed, so locate its archive and link it.
    match find_static_lib(&dst, &["capstone.lib", "capstone_static.lib", "libcapstone.a"]) {
        Some((dir, lib)) => {
            println!("cargo:rustc-link-search=native={}", dir.display());
            println!("cargo:rustc-link-lib=static={}", lib);
        }
        None => println!(
            "cargo:warning=capstone static library not found under {}",
            dst.display()
        ),
    }

    // The engine has C++ translation units (engine/analysis/*.cpp). On MSVC the
    // C++ runtime is linked automatically by the MSVC toolchain; nothing extra
    // is required here. On a GNU/Unix host we would need the C++ stdlib, but
    // this project targets MSVC, so we keep the link line minimal.
    if !cfg!(target_env = "msvc") {
        // Best-effort for non-MSVC dev hosts (e.g. CI on Linux).
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }

    // --- 2. generate FFI bindings with bindgen -----------------------------
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // The caller is expected to set LIBCLANG_PATH (offline toolchain location).
    // If it is present, forward it so bindgen's libloading finds libclang.
    if let Ok(libclang) = env::var("LIBCLANG_PATH") {
        // bindgen reads LIBCLANG_PATH from the environment itself; re-exporting
        // is harmless and makes the dependency explicit in build logs.
        println!("cargo:rerun-if-env-changed=LIBCLANG_PATH");
        // Setting it again is a no-op if unchanged but guards against a parent
        // build script having cleared it.
        env::set_var("LIBCLANG_PATH", &libclang);
    }
    println!("cargo:rerun-if-env-changed=LIBCLANG_PATH");

    let header_str = header_abs.to_string_lossy().into_owned();
    let bindings = bindgen::Builder::default()
        .header(&header_str)
        // include dir so #include <stdint.h>/<stddef.h> + the header resolve.
        .clang_arg(format!("-I{}", include_abs.display()))
        // core types (no_std-friendly): emit ::core::ffi / ::core::option etc.
        .use_core()
        // Only surface the engine ABI, not the entire libc transitive closure.
        .allowlist_function("ds_.*")
        .allowlist_type("ds_.*")
        // The header also defines anonymous enums for DS_REF_* / DS_FLAG_* /
        // DS_XREF_*; allow those constants through by name too.
        .allowlist_var("DS_.*")
        // Layout tests can be noisy across platforms; the wrapper relies on the
        // ABI being correct, not on bindgen's generated asserts.
        .layout_tests(false)
        // No doc-comment passthrough; keeps generated file lean & libclang-quiet.
        .generate_comments(false)
        .generate()
        .expect("bindgen failed to generate bindings for disasm.h");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed to write bindings.rs");

    // --- 3. rerun triggers --------------------------------------------------
    println!("cargo:rerun-if-changed={}", header_abs.display());
    println!("cargo:rerun-if-changed=build.rs");
    watch_engine_sources(&engine_abs);
}

/// Recursively search `root` for the first file matching any of `names`,
/// returning (containing_dir, link_name). `link_name` strips a leading "lib" and
/// the extension so it can be passed to `rustc-link-lib=static=<name>`.
fn find_static_lib(root: &Path, names: &[&str]) -> Option<(PathBuf, String)> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Some(fname) = path.file_name().and_then(|s| s.to_str()) {
                for n in names {
                    if fname.eq_ignore_ascii_case(n) {
                        let stem = n
                            .trim_end_matches(".lib")
                            .trim_end_matches(".a")
                            .trim_start_matches("lib")
                            .to_string();
                        if let Some(parent) = path.parent() {
                            return Some((parent.to_path_buf(), stem));
                        }
                    }
                }
            }
        }
    }
    None
}

/// Emit `cargo:rerun-if-changed` for every engine source so editing the C/C++
/// implementation re-triggers the static-lib rebuild.
fn watch_engine_sources(engine_abs: &Path) {
    let dirs = [
        engine_abs.join("src"),
        engine_abs.join("analysis"),
        engine_abs.join("include"),
    ];
    // Watch the CMakeLists too (glob membership / options can change).
    let cmake_lists = engine_abs.join("CMakeLists.txt");
    if cmake_lists.exists() {
        println!("cargo:rerun-if-changed={}", cmake_lists.display());
    }
    for dir in &dirs {
        // Watch the directory itself (added/removed files) ...
        println!("cargo:rerun-if-changed={}", dir.display());
        // ... and each file within (content edits).
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    println!("cargo:rerun-if-changed={}", path.display());
                }
            }
        }
    }
}
