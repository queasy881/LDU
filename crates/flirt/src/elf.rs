//! ELF relocatable-object reader (the members of a GNU `.a`: libstdc++, libc++,
//! libc). Mirrors `coff.rs`: per-function bytes, relocated (variant) byte offsets,
//! and referenced external symbols.

use crate::coff::ObjFunc;

const EM_X86_64: u16 = 62;
const SHF_EXECINSTR: u64 = 0x4;
const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_PROGBITS: u32 = 1;

/// Parse an ELF64 relocatable object; return its code functions.
pub fn functions(obj: &[u8]) -> Vec<ObjFunc> {
    let mut out = Vec::new();
    if obj.len() < 64 || &obj[0..4] != [0x7f, b'E', b'L', b'F'] || obj[4] != 2 {
        return out; // ELF64 little-endian only
    }
    if rd_u16(obj, 18) != EM_X86_64 {
        return out;
    }
    let shoff = rd_u64(obj, 40) as usize;
    let shentsize = rd_u16(obj, 58) as usize;
    let shnum = rd_u16(obj, 60) as usize;
    if shentsize < 64 || shoff == 0 {
        return out;
    }

    struct Sec { typ: u32, flags: u64, offset: usize, size: usize, link: u32, info: u32, entsize: usize }
    let mut secs: Vec<Sec> = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let b = shoff + i * shentsize;
        if b + 64 > obj.len() {
            break;
        }
        secs.push(Sec {
            typ: rd_u32(obj, b + 4),
            flags: rd_u64(obj, b + 8),
            offset: rd_u64(obj, b + 24) as usize,
            size: rd_u64(obj, b + 32) as usize,
            link: rd_u32(obj, b + 40),
            info: rd_u32(obj, b + 44),
            entsize: rd_u64(obj, b + 56) as usize,
        });
    }

    // symbol table (there is usually exactly one .symtab)
    let symtab = secs.iter().enumerate().find(|(_, s)| s.typ == SHT_SYMTAB);
    let (sym_sec_i, sym_sec) = match symtab {
        Some(x) => x,
        None => return out,
    };
    let _ = sym_sec_i;
    let strtab = secs.get(sym_sec.link as usize);
    let str_off = strtab.map(|s| s.offset).unwrap_or(0);
    let str_size = strtab.map(|s| s.size).unwrap_or(0);
    let sym_entsize = if sym_sec.entsize >= 24 { sym_sec.entsize } else { 24 };
    let nsyms = if sym_entsize > 0 { sym_sec.size / sym_entsize } else { 0 };

    struct Sym { name: String, value: u64, size: u64, shndx: u16, typ: u8 }
    let mut syms: Vec<Sym> = Vec::with_capacity(nsyms);
    for i in 0..nsyms {
        let b = sym_sec.offset + i * sym_entsize;
        if b + 24 > obj.len() {
            break;
        }
        let name_off = rd_u32(obj, b) as usize;
        let info = obj[b + 4];
        let shndx = rd_u16(obj, b + 6);
        let value = rd_u64(obj, b + 8);
        let size = rd_u64(obj, b + 16);
        syms.push(Sym { name: str_at(obj, str_off, str_size, name_off), value, size, shndx, typ: info & 0xf });
    }

    // for each code section, gather its RELA and its FUNC symbols
    for (sidx, sec) in secs.iter().enumerate() {
        if sec.typ != SHT_PROGBITS || sec.flags & SHF_EXECINSTR == 0 || sec.size == 0 {
            continue;
        }
        if sec.offset + sec.size > obj.len() {
            continue;
        }
        let data = &obj[sec.offset..sec.offset + sec.size];

        // relocations targeting this section (RELA with sh_info == sidx)
        struct Rel { off: usize, sym: u32, typ: u32 }
        let mut rels: Vec<Rel> = Vec::new();
        for rs in &secs {
            if rs.typ != SHT_RELA || rs.info as usize != sidx {
                continue;
            }
            let es = if rs.entsize >= 24 { rs.entsize } else { 24 };
            let n = if es > 0 { rs.size / es } else { 0 };
            for r in 0..n {
                let b = rs.offset + r * es;
                if b + 24 > obj.len() {
                    break;
                }
                let off = rd_u64(obj, b) as usize;
                let info = rd_u64(obj, b + 8);
                rels.push(Rel { off, sym: (info >> 32) as u32, typ: (info & 0xffff_ffff) as u32 });
            }
        }

        // function starts = FUNC symbols in this section
        let mut funcs: Vec<(u64, u64, String)> = Vec::new(); // (value, size, name)
        for s in &syms {
            if s.shndx as usize == sidx && s.typ == 2 && !s.name.is_empty() && (s.value as usize) < sec.size {
                funcs.push((s.value, s.size, s.name.clone()));
            }
        }
        funcs.sort_by_key(|x| x.0);
        funcs.dedup_by_key(|x| x.0);

        for k in 0..funcs.len() {
            let start = funcs[k].0 as usize;
            let mut end = if funcs[k].1 > 0 {
                start + funcs[k].1 as usize
            } else if k + 1 < funcs.len() {
                funcs[k + 1].0 as usize
            } else {
                sec.size
            };
            if end > sec.size {
                end = sec.size;
            }
            if end <= start {
                continue;
            }
            let code = data[start..end].to_vec();
            let mut variant = vec![false; code.len()];
            let mut refs: Vec<(u16, String)> = Vec::new();
            for r in &rels {
                if r.off < start || r.off >= end {
                    continue;
                }
                let off = r.off - start;
                let sz = reloc_size(r.typ);
                for b in 0..sz {
                    if off + b < variant.len() {
                        variant[off + b] = true;
                    }
                }
                if let Some(t) = syms.get(r.sym as usize) {
                    if t.shndx == 0 && !t.name.is_empty() && off <= u16::MAX as usize {
                        refs.push((off as u16, t.name.clone()));
                    }
                }
            }
            out.push(ObjFunc { name: funcs[k].2.clone(), code, variant, refs });
        }
    }
    out
}

/// Variant byte count for an x86-64 ELF relocation type.
fn reloc_size(typ: u32) -> usize {
    match typ {
        0 => 0,             // NONE
        1 => 8,             // 64
        2 | 4 => 4,         // PC32 / PLT32
        9 | 19 | 41 | 42 => 4, // GOTPCREL / TLS variants
        10 | 11 => 4,       // 32 / 32S
        24 | 25 => 8,       // PC64 / GOTOFF64
        26 => 4,            // GOTPC32
        _ => 4,
    }
}

fn str_at(obj: &[u8], base: usize, size: usize, off: usize) -> String {
    if off >= size {
        return String::new();
    }
    let p = base + off;
    if p >= obj.len() {
        return String::new();
    }
    let end = obj[p..].iter().position(|&c| c == 0).map(|e| p + e).unwrap_or(obj.len());
    String::from_utf8_lossy(&obj[p..end]).into_owned()
}

fn rd_u16(b: &[u8], o: usize) -> u16 { if o + 2 <= b.len() { u16::from_le_bytes([b[o], b[o + 1]]) } else { 0 } }
fn rd_u32(b: &[u8], o: usize) -> u32 { if o + 4 <= b.len() { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) } else { 0 } }
fn rd_u64(b: &[u8], o: usize) -> u64 { if o + 8 <= b.len() { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) } else { 0 } }
