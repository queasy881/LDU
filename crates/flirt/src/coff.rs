//! COFF object reader (the members of an MSVC `.lib`). Extracts each function's
//! bytes, the byte offsets the linker relocates (variant/wildcard bytes), and the
//! external symbols it references — everything a signature needs.

pub struct ObjFunc {
    pub name: String,
    pub code: Vec<u8>,
    pub variant: Vec<bool>,       // per-byte: true = relocated (wildcard)
    pub refs: Vec<(u16, String)>, // (offset, external symbol) — called library fns
}

const MACH_AMD64: u16 = 0x8664;
const SCN_CODE: u32 = 0x0000_0020;     // IMAGE_SCN_CNT_CODE
const SCN_EXEC: u32 = 0x2000_0000;     // IMAGE_SCN_MEM_EXECUTE

struct Sym {
    name: String,
    value: u32,
    section: i16,
    is_func: bool,
    storage: u8,
}

/// Parse a COFF object; return its code functions.
pub fn functions(obj: &[u8]) -> Vec<ObjFunc> {
    let mut out = Vec::new();
    if obj.len() < 20 {
        return out;
    }
    let machine = rd_u16(obj, 0);
    if machine != MACH_AMD64 {
        return out; // x64 only for now
    }
    let num_sections = rd_u16(obj, 2) as usize;
    let sym_ptr = rd_u32(obj, 8) as usize;
    let num_syms = rd_u32(obj, 12) as usize;
    let opt_hdr = rd_u16(obj, 16) as usize;

    // string table follows the symbol table (each symbol slot is 18 bytes)
    let strtab_off = sym_ptr + num_syms * 18;

    // ---- symbols (indexed incl. aux slots so relocations resolve correctly) ----
    let mut syms: Vec<Option<Sym>> = Vec::with_capacity(num_syms);
    {
        let mut i = 0usize;
        while i < num_syms {
            let base = sym_ptr + i * 18;
            if base + 18 > obj.len() {
                break;
            }
            let name = sym_name(obj, base, strtab_off);
            let value = rd_u32(obj, base + 8);
            let section = rd_u16(obj, base + 12) as i16;
            let typ = rd_u16(obj, base + 14);
            let storage = obj[base + 16];
            let naux = obj[base + 17] as usize;
            let is_func = (typ >> 8) == 0x20; // DTYPE FUNCTION in the high byte
            syms.push(Some(Sym { name, value, section, is_func, storage }));
            for _ in 0..naux {
                syms.push(None);
            }
            i += 1 + naux;
        }
        // pad in case counts drifted
        while syms.len() < num_syms {
            syms.push(None);
        }
    }

    // ---- sections ----
    let sec_base = 20 + opt_hdr;
    for si in 0..num_sections {
        let sh = sec_base + si * 40;
        if sh + 40 > obj.len() {
            break;
        }
        let chars = rd_u32(obj, sh + 36);
        if chars & (SCN_CODE | SCN_EXEC) == 0 {
            continue; // not code
        }
        let raw_size = rd_u32(obj, sh + 16) as usize;
        let raw_ptr = rd_u32(obj, sh + 20) as usize;
        let rel_ptr = rd_u32(obj, sh + 24) as usize;
        let nrel = rd_u16(obj, sh + 32) as usize;
        if raw_ptr == 0 || raw_ptr + raw_size > obj.len() || raw_size == 0 {
            continue;
        }
        let sec_no = (si + 1) as i16;
        let data = &obj[raw_ptr..raw_ptr + raw_size];

        // relocations for this section
        struct Rel { va: u32, sym: u32, typ: u16 }
        let mut rels: Vec<Rel> = Vec::with_capacity(nrel);
        for r in 0..nrel {
            let rb = rel_ptr + r * 10;
            if rb + 10 > obj.len() {
                break;
            }
            rels.push(Rel { va: rd_u32(obj, rb), sym: rd_u32(obj, rb + 4), typ: rd_u16(obj, rb + 8) });
        }

        // function starts in this section = defined symbols pointing here
        let mut starts: Vec<(u32, String)> = Vec::new();
        for s in syms.iter().flatten() {
            if s.section == sec_no && (s.is_func || s.storage == 2) && (s.value as usize) < raw_size {
                starts.push((s.value, s.name.clone()));
            }
        }
        if starts.is_empty() {
            continue;
        }
        starts.sort_by_key(|x| x.0);
        starts.dedup_by_key(|x| x.0);

        for k in 0..starts.len() {
            let start = starts[k].0 as usize;
            let end = if k + 1 < starts.len() {
                starts[k + 1].0 as usize
            } else {
                raw_size
            };
            if end <= start || end > raw_size {
                continue;
            }
            let code = data[start..end].to_vec();
            let mut variant = vec![false; code.len()];
            let mut refs: Vec<(u16, String)> = Vec::new();
            for r in &rels {
                let va = r.va as usize;
                if va < start || va >= end {
                    continue;
                }
                let off = va - start;
                let sz = reloc_size(r.typ);
                for b in 0..sz {
                    if off + b < variant.len() {
                        variant[off + b] = true;
                    }
                }
                // referenced external symbol name (a called library fn) for tie-breaks
                if let Some(Some(t)) = syms.get(r.sym as usize) {
                    if t.section == 0 && !t.name.is_empty() && off <= u16::MAX as usize {
                        refs.push((off as u16, t.name.clone()));
                    }
                }
            }
            out.push(ObjFunc { name: starts[k].1.clone(), code, variant, refs });
        }
    }
    out
}

/// Variant byte count for an AMD64 relocation type.
fn reloc_size(typ: u16) -> usize {
    match typ {
        0 => 0,       // ABSOLUTE
        1 => 8,       // ADDR64
        2 | 3 => 4,   // ADDR32 / ADDR32NB
        4..=9 => 4,   // REL32 / REL32_1..5
        0xA => 2,     // SECTION
        0xB => 4,     // SECREL
        0xC => 1,     // SECREL7
        _ => 4,
    }
}

fn sym_name(obj: &[u8], base: usize, strtab_off: usize) -> String {
    // if the first 4 name bytes are zero, bytes[4..8] are a string-table offset
    if rd_u32(obj, base) == 0 {
        let off = rd_u32(obj, base + 4) as usize;
        let p = strtab_off + off;
        if p < obj.len() {
            let end = obj[p..].iter().position(|&c| c == 0).map(|e| p + e).unwrap_or(obj.len());
            return String::from_utf8_lossy(&obj[p..end]).into_owned();
        }
        return String::new();
    }
    let s = &obj[base..base + 8];
    let end = s.iter().position(|&c| c == 0).unwrap_or(8);
    String::from_utf8_lossy(&s[..end]).into_owned()
}

fn rd_u16(b: &[u8], o: usize) -> u16 {
    if o + 2 <= b.len() { u16::from_le_bytes([b[o], b[o + 1]]) } else { 0 }
}
fn rd_u32(b: &[u8], o: usize) -> u32 {
    if o + 4 <= b.len() { u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) } else { 0 }
}
