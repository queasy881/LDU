use binparser::BinaryMeta;
#[test]
fn resolve_long_section_names() {
    let path = r"C:\Users\User\Downloads\sd\scratch_flirt\tg.exe";
    let bytes = std::fs::read(path).expect("read tg.exe");
    let m = BinaryMeta::parse(&bytes).expect("parse");
    eprintln!("sections in tg.exe:");
    let mut has_slash = false;
    for s in &m.segments {
        eprintln!("  {:20} rva={:#x} vsize={:#x}", s.name, s.rva, s.vsize);
        if s.name.starts_with('/') { has_slash = true; }
    }
    assert!(!has_slash, "a /N long-name section was left unresolved");
}
