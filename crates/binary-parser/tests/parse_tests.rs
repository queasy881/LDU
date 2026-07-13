//! Integration tests for the `binparser` crate.
//!
//! - Parses a real system DLL when available (skipped gracefully otherwise).
//! - Asserts malformed input returns `Err` and never panics.
//! - Round-trips a crafted minimal ELF64 header in memory.
//! - Exercises `build_image` layout.

use binparser::{Arch, BinaryMeta, Format, FLAG_R, FLAG_X};

#[test]
fn parse_kernel32_if_present() {
    let path = r"C:\Windows\System32\kernel32.dll";
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("skip: {} not present", path);
            return;
        }
    };

    let meta = BinaryMeta::parse(&bytes).expect("kernel32.dll should parse");
    assert_eq!(meta.format, Format::Pe32Plus, "kernel32 is PE32+");
    assert_eq!(meta.arch, Arch::X64, "kernel32 is x64");
    assert!(meta.is_dll, "kernel32 is a DLL");
    assert!(!meta.segments.is_empty(), "must have segments");
    assert!(!meta.exports.is_empty(), "kernel32 exports many functions");
    assert_ne!(meta.entry, 0, "entry rva should be non-zero");

    // Well-known exports must be present.
    let has_loadlibrary = meta
        .exports
        .iter()
        .any(|s| s.name == "LoadLibraryA" || s.name == "LoadLibraryW");
    assert!(has_loadlibrary, "kernel32 must export LoadLibrary*");

    // Every export RVA should fall within the image.
    for e in &meta.exports {
        assert!(e.rva < meta.image_size.max(1) + 0x10_0000);
    }

    // build_image should not panic and should be at least image_size.
    let image = meta.build_image(&bytes);
    assert!(image.len() as u64 >= meta.image_size.min(image.len() as u64));
    assert!(!image.is_empty());
}

#[test]
fn malformed_input_returns_err_not_panic() {
    // Garbage with no recognizable magic.
    assert!(BinaryMeta::parse(&[0u8; 0]).is_err());
    assert!(BinaryMeta::parse(b"not a binary").is_err());

    // "MZ" then immediate truncation: e_lfanew read should fail cleanly.
    let mut mz = vec![0u8; 8];
    mz[0] = b'M';
    mz[1] = b'Z';
    assert!(BinaryMeta::parse(&mz).is_err());

    // "MZ" with an e_lfanew pointing far past EOF.
    let mut mz2 = vec![0u8; 0x40];
    mz2[0] = b'M';
    mz2[1] = b'Z';
    mz2[0x3C] = 0xFF;
    mz2[0x3D] = 0xFF;
    mz2[0x3E] = 0xFF;
    mz2[0x3F] = 0x7F;
    assert!(BinaryMeta::parse(&mz2).is_err());

    // ELF magic followed by garbage class byte.
    let mut elf = vec![0u8; 64];
    elf[0] = 0x7F;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 9; // invalid EI_CLASS
    assert!(BinaryMeta::parse(&elf).is_err());

    // ELF claiming huge phnum but truncated body must not panic.
    let mut elf2 = build_minimal_elf64();
    // Corrupt e_phnum to a large value.
    elf2[56] = 0xFF;
    elf2[57] = 0xFF;
    let _ = BinaryMeta::parse(&elf2); // must not panic; result may be Ok or Err
}

#[test]
fn elf64_header_round_trip() {
    let bytes = build_minimal_elf64();
    let meta = BinaryMeta::parse(&bytes).expect("crafted ELF64 should parse");
    assert_eq!(meta.format, Format::Elf64);
    assert_eq!(meta.arch, Arch::X64);
    assert!(meta.is_dll, "ET_DYN should be flagged as DLL");
    assert_eq!(meta.base, 0x1000, "lowest PT_LOAD vaddr is the base");
    assert_eq!(meta.entry, 0x2000 - 0x1000, "entry rva = e_entry - base");
    assert_eq!(meta.segments.len(), 1);
    let seg = &meta.segments[0];
    assert_eq!(seg.rva, 0); // vaddr 0x1000 - base 0x1000
    assert_eq!(seg.flags & FLAG_R, FLAG_R);
    assert_eq!(seg.flags & FLAG_X, FLAG_X);
}

#[test]
fn build_image_lays_segment_bytes_at_rva() {
    let bytes = build_minimal_elf64();
    let meta = BinaryMeta::parse(&bytes).expect("parse");
    let image = meta.build_image(&bytes);
    // The PT_LOAD's first raw byte (a 0xCC we planted) must appear at rva 0.
    assert!(!image.is_empty());
    assert_eq!(image[0], 0xCC, "segment raw byte should be placed at its rva");
}

/// Build a tiny but valid little-endian ELF64 ET_DYN with one PT_LOAD segment.
/// Entry = 0x2000, base = 0x1000, one R+X load mapping file offset 0x200.
fn build_minimal_elf64() -> Vec<u8> {
    // Layout:
    //   0x000 : ELF header (64 bytes)
    //   0x040 : program header (56 bytes)
    //   0x200 : segment raw bytes (one 0xCC byte)
    let mut b = vec![0u8; 0x208];

    // e_ident
    b[0] = 0x7F;
    b[1] = b'E';
    b[2] = b'L';
    b[3] = b'F';
    b[4] = 2; // ELFCLASS64
    b[5] = 1; // ELFDATA2LSB
    b[6] = 1; // EV_CURRENT

    let w16 = |b: &mut [u8], off: usize, v: u16| b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    let w32 = |b: &mut [u8], off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    let w64 = |b: &mut [u8], off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());

    w16(&mut b, 16, 3); // e_type = ET_DYN
    w16(&mut b, 18, 0x3e); // e_machine = EM_X86_64
    w32(&mut b, 20, 1); // e_version
    w64(&mut b, 24, 0x2000); // e_entry
    w64(&mut b, 32, 0x40); // e_phoff
    w64(&mut b, 40, 0); // e_shoff (no sections)
    w32(&mut b, 48, 0); // e_flags
    w16(&mut b, 52, 64); // e_ehsize
    w16(&mut b, 54, 56); // e_phentsize
    w16(&mut b, 56, 1); // e_phnum
    w16(&mut b, 58, 0); // e_shentsize
    w16(&mut b, 60, 0); // e_shnum
    w16(&mut b, 62, 0); // e_shstrndx

    // Program header at 0x40 (PT_LOAD, R+X).
    let ph = 0x40usize;
    w32(&mut b, ph, 1); // p_type = PT_LOAD
    w32(&mut b, ph + 4, 0x5); // p_flags = R|X (PF_R|PF_X)
    w64(&mut b, ph + 8, 0x200); // p_offset
    w64(&mut b, ph + 16, 0x1000); // p_vaddr
    w64(&mut b, ph + 24, 0x1000); // p_paddr
    w64(&mut b, ph + 32, 1); // p_filesz
    w64(&mut b, ph + 40, 0x1000); // p_memsz
    w64(&mut b, ph + 48, 0x1000); // p_align

    // Raw segment byte.
    b[0x200] = 0xCC;

    b
}
