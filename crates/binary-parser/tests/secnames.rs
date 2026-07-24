//! Long section names (`/N` pointing into the COFF string table) must be
//! resolved to their real names by the PE parser.
//!
//! Needs a binary that actually HAS long section names — MSVC emits them for
//! `/GL` link-time-codegen builds, which is what `_qa/fixtures/flirt/build.ps1`
//! produces. Set `DS_SECNAME_BIN` to point at any other such binary. The test
//! SKIPS rather than failing when none is available, so a fresh checkout is
//! green without needing an MSVC toolchain (it previously hardcoded a path on
//! one developer's machine and panicked everywhere else).

use binparser::BinaryMeta;

fn candidate() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("DS_SECNAME_BIN") {
        let p = std::path::PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())?;
    let p = root.join("_qa").join("fixtures").join("flirt").join("tg.exe");
    p.exists().then_some(p)
}

#[test]
fn resolve_long_section_names() {
    let Some(path) = candidate() else {
        eprintln!(
            "[skip] no binary with long section names: set DS_SECNAME_BIN, or run \
             _qa/fixtures/flirt/build.ps1"
        );
        return;
    };
    let bytes = std::fs::read(&path).expect("read test binary");
    let m = BinaryMeta::parse(&bytes).expect("parse");
    eprintln!("sections in {}:", path.display());
    let mut has_slash = false;
    for s in &m.segments {
        eprintln!("  {:20} rva={:#x} vsize={:#x}", s.name, s.rva, s.vsize);
        if s.name.starts_with('/') {
            has_slash = true;
        }
    }
    assert!(!has_slash, "a /N long-name section was left unresolved");
}
