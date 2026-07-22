//! ELF parser. Hand-rolled, bounds-checked, std-only.
//!
//! Reads the ELF header, PT_LOAD program headers (for segments), and the
//! section table to locate `.dynsym`/`.symtab` plus their string tables for
//! function symbol recovery. Big-endian ELF is supported via the `EI_DATA`
//! byte. All reads are checked.

use crate::{rd_cstr, Arch, BinaryMeta, Format, Segment, Symbol, FLAG_R, FLAG_W, FLAG_X};

// e_type
const ET_DYN: u16 = 3;

// p_type
const PT_LOAD: u32 = 1;

// p_flags
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

// sh_type
const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;

// st_info type (low nibble)
const STT_FUNC: u8 = 2;

// SHN_UNDEF
const SHN_UNDEF: u16 = 0;

// e_machine
const EM_386: u16 = 0x03;
const EM_ARM: u16 = 0x28;
const EM_X86_64: u16 = 0x3e;
const EM_AARCH64: u16 = 0xb7;

/// Endian-aware checked readers bound to one file's `EI_DATA`.
struct Rdr<'a> {
    b: &'a [u8],
    le: bool,
}

impl<'a> Rdr<'a> {
    fn u16(&self, off: usize) -> Option<u16> {
        let s = self.b.get(off..off.checked_add(2)?)?;
        let a = [s[0], s[1]];
        Some(if self.le {
            u16::from_le_bytes(a)
        } else {
            u16::from_be_bytes(a)
        })
    }
    fn u32(&self, off: usize) -> Option<u32> {
        let s = self.b.get(off..off.checked_add(4)?)?;
        let a = [s[0], s[1], s[2], s[3]];
        Some(if self.le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }
    fn u64(&self, off: usize) -> Option<u64> {
        let s = self.b.get(off..off.checked_add(8)?)?;
        let a = [s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]];
        Some(if self.le {
            u64::from_le_bytes(a)
        } else {
            u64::from_be_bytes(a)
        })
    }
}

struct Section {
    sh_type: u32,
    sh_link: u32,
    sh_offset: u64,
    sh_size: u64,
    sh_entsize: u64,
}

pub(crate) fn parse(bytes: &[u8]) -> Result<BinaryMeta, String> {
    // e_ident: magic [0..4] already verified. EI_CLASS @ 4, EI_DATA @ 5.
    let ei_class = *bytes.get(4).ok_or("truncated ELF e_ident")?;
    let ei_data = *bytes.get(5).ok_or("truncated ELF e_ident")?;
    let is64 = match ei_class {
        1 => false,
        2 => true,
        other => return Err(format!("invalid ELF class {}", other)),
    };
    let le = match ei_data {
        1 => true,
        2 => false,
        other => return Err(format!("invalid ELF data encoding {}", other)),
    };
    let r = Rdr { b: bytes, le };

    let e_type = r.u16(16).ok_or("truncated ELF header (e_type)")?;
    let e_machine = r.u16(18).ok_or("truncated ELF header (e_machine)")?;

    let arch = match e_machine {
        EM_386 => Arch::X86,
        EM_X86_64 => Arch::X64,
        EM_ARM => Arch::Arm,
        EM_AARCH64 => Arch::Arm64,
        _ => Arch::Unknown,
    };
    let format = if is64 { Format::Elf64 } else { Format::Elf32 };
    let is_dll = e_type == ET_DYN;

    // Header fields differ in width between ELF32 and ELF64.
    let (e_entry, e_phoff, e_shoff, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) =
        if is64 {
            (
                r.u64(24).ok_or("truncated ELF64 header")?,        // e_entry
                r.u64(32).ok_or("truncated ELF64 header")? as usize, // e_phoff
                r.u64(40).ok_or("truncated ELF64 header")? as usize, // e_shoff
                r.u16(54).ok_or("truncated ELF64 header")? as usize, // e_phentsize
                r.u16(56).ok_or("truncated ELF64 header")? as usize, // e_phnum
                r.u16(58).ok_or("truncated ELF64 header")? as usize, // e_shentsize
                r.u16(60).ok_or("truncated ELF64 header")? as usize, // e_shnum
                r.u16(62).ok_or("truncated ELF64 header")? as usize, // e_shstrndx
            )
        } else {
            (
                r.u32(24).ok_or("truncated ELF32 header")? as u64,   // e_entry
                r.u32(28).ok_or("truncated ELF32 header")? as usize, // e_phoff
                r.u32(32).ok_or("truncated ELF32 header")? as usize, // e_shoff
                r.u16(42).ok_or("truncated ELF32 header")? as usize, // e_phentsize
                r.u16(44).ok_or("truncated ELF32 header")? as usize, // e_phnum
                r.u16(46).ok_or("truncated ELF32 header")? as usize, // e_shentsize
                r.u16(48).ok_or("truncated ELF32 header")? as usize, // e_shnum
                r.u16(50).ok_or("truncated ELF32 header")? as usize, // e_shstrndx
            )
        };

    // ---- program headers -> PT_LOAD segments ----
    let phnum = e_phnum.min(65536);
    let mut loads: Vec<(u64, u64, u64, u64, u32)> = Vec::new(); // (vaddr, memsz, off, filesz, flags)
    let mut min_vaddr: Option<u64> = None;
    for i in 0..phnum {
        let ph = e_phoff + i * e_phentsize;
        let p_type = match r.u32(ph) {
            Some(v) => v,
            None => break,
        };
        if p_type != PT_LOAD {
            continue;
        }
        let (p_flags, p_offset, p_vaddr, p_filesz, p_memsz) = if is64 {
            (
                r.u32(ph + 4).unwrap_or(0),
                r.u64(ph + 8).unwrap_or(0),
                r.u64(ph + 16).unwrap_or(0),
                r.u64(ph + 32).unwrap_or(0),
                r.u64(ph + 40).unwrap_or(0),
            )
        } else {
            (
                r.u32(ph + 24).unwrap_or(0),
                r.u32(ph + 4).unwrap_or(0) as u64,
                r.u32(ph + 8).unwrap_or(0) as u64,
                r.u32(ph + 16).unwrap_or(0) as u64,
                r.u32(ph + 20).unwrap_or(0) as u64,
            )
        };
        min_vaddr = Some(match min_vaddr {
            Some(m) => m.min(p_vaddr),
            None => p_vaddr,
        });
        loads.push((p_vaddr, p_memsz, p_offset, p_filesz, p_flags));
    }

    // Base = lowest PT_LOAD vaddr (0 for PIE/ET_DYN that loads at 0).
    let base = min_vaddr.unwrap_or(0);

    let mut segments: Vec<Segment> = Vec::with_capacity(loads.len());
    for (idx, (vaddr, memsz, off, filesz, pflags)) in loads.iter().enumerate() {
        let mut flags = 0u32;
        if pflags & PF_R != 0 {
            flags |= FLAG_R;
        }
        if pflags & PF_W != 0 {
            flags |= FLAG_W;
        }
        if pflags & PF_X != 0 {
            flags |= FLAG_X;
        }
        if flags == 0 {
            flags = FLAG_R;
        }
        let name = if flags & FLAG_X != 0 {
            "LOAD.text".to_string()
        } else if flags & FLAG_W != 0 {
            "LOAD.data".to_string()
        } else {
            format!("LOAD{}", idx)
        };
        segments.push(Segment {
            name,
            rva: vaddr.saturating_sub(base),
            vsize: *memsz,
            flags,
            file_off: *off,
            file_size: *filesz,
        });
    }

    let entry = e_entry.saturating_sub(base);

    let mut image_size = 0u64;
    for seg in &segments {
        let end = seg.rva.saturating_add(seg.vsize);
        if end > image_size {
            image_size = end;
        }
    }

    // ---- section headers -> symbol tables ----
    let mut sections: Vec<Section> = Vec::new();
    let shnum = e_shnum.min(65536);
    for i in 0..shnum {
        let sh = e_shoff + i * e_shentsize;
        let sh_type = match r.u32(sh + 4) {
            Some(v) => v,
            None => break,
        };
        let (sh_offset, sh_size, sh_link, sh_entsize) = if is64 {
            (
                r.u64(sh + 24).unwrap_or(0),
                r.u64(sh + 32).unwrap_or(0),
                r.u32(sh + 40).unwrap_or(0),
                r.u64(sh + 56).unwrap_or(0),
            )
        } else {
            (
                r.u32(sh + 16).unwrap_or(0) as u64,
                r.u32(sh + 20).unwrap_or(0) as u64,
                r.u32(sh + 24).unwrap_or(0),
                r.u32(sh + 36).unwrap_or(0) as u64,
            )
        };
        sections.push(Section {
            sh_type,
            sh_link,
            sh_offset,
            sh_size,
            sh_entsize,
        });
    }
    let _ = e_shstrndx; // section names not required for symbol recovery

    let mut exports: Vec<Symbol> = Vec::new();
    let mut imports: Vec<Symbol> = Vec::new();

    // Prefer .symtab (richer) if present; otherwise .dynsym. Iterate any symbol
    // section so a stripped-but-dynamic binary still yields exports.
    for sec in &sections {
        if sec.sh_type != SHT_SYMTAB && sec.sh_type != SHT_DYNSYM {
            continue;
        }
        let entsize = if sec.sh_entsize != 0 {
            sec.sh_entsize as usize
        } else if is64 {
            24
        } else {
            16
        };
        if entsize == 0 {
            continue;
        }
        // Associated string table section.
        let strtab = match sections.get(sec.sh_link as usize) {
            Some(s) => s,
            None => continue,
        };
        let str_off = strtab.sh_offset as usize;
        let str_size = strtab.sh_size as usize;

        let count = (sec.sh_size / sec.sh_entsize.max(entsize as u64)) as usize;
        let count = count.min(2_000_000);
        for i in 0..count {
            let so = sec.sh_offset as usize + i * entsize;
            // Layout differs between ELF32 and ELF64 symbol entries.
            let (st_name, st_info, st_shndx, st_value) = if is64 {
                (
                    r.u32(so).unwrap_or(0),
                    *bytes.get(so + 4).unwrap_or(&0),
                    r.u16(so + 6).unwrap_or(0),
                    r.u64(so + 8).unwrap_or(0),
                )
            } else {
                (
                    r.u32(so).unwrap_or(0),
                    *bytes.get(so + 12).unwrap_or(&0),
                    r.u16(so + 14).unwrap_or(0),
                    r.u32(so + 4).unwrap_or(0) as u64,
                )
            };
            let sym_type = st_info & 0x0f;
            if sym_type != STT_FUNC {
                continue;
            }
            // Resolve the name from the linked string table.
            let name_off = str_off.saturating_add(st_name as usize);
            let name = if (st_name as usize) < str_size {
                rd_cstr(bytes, name_off, 4096).unwrap_or_default()
            } else {
                String::new()
            };
            if name.is_empty() {
                continue;
            }
            if st_shndx == SHN_UNDEF || st_value == 0 {
                // Undefined function symbol -> an import (best effort, rva 0 ok).
                // ELF does not record a per-symbol owning library here.
                imports.push(Symbol {
                    rva: st_value.saturating_sub(base),
                    name,
                    module: None,
                });
            } else {
                exports.push(Symbol {
                    rva: st_value.saturating_sub(base),
                    name,
                    module: None,
                });
            }
        }
        // If .symtab was found and produced results, that's the best source;
        // keep scanning .dynsym too so PLT/import names are also captured, but
        // exports from .symtab already cover defined functions. Dedup below.
    }

    dedup_symbols(&mut exports);
    dedup_symbols(&mut imports);

    Ok(BinaryMeta {
        format,
        arch,
        base,
        entry,
        is_dll,
        image_size,
        segments,
        exports,
        imports,
        tls_callbacks: Vec::new(),
    })
}

/// Stable de-duplication on (rva, name) preserving first occurrence.
fn dedup_symbols(v: &mut Vec<Symbol>) {
    use std::collections::HashSet;
    let mut seen: HashSet<(u64, String)> = HashSet::new();
    v.retain(|s| seen.insert((s.rva, s.name.clone())));
}
