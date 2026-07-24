//! DWARF `.debug_info` reader — function names and addresses.
//!
//! This is the ELF/Mach-O counterpart of the PDB loader: without it a binary
//! built with `-g` decompiles as blind as a stripped one, because `.symtab`
//! carries no name for a `static` function that was never exported and no
//! parameter names at all.
//!
//! Deliberately narrow: it walks compilation units for `DW_TAG_subprogram` DIEs
//! that have a name and a `DW_AT_low_pc`, and returns them as symbols. Types and
//! parameters are NOT decoded yet.
//!
//! The crux is form skipping. Attribute values are laid out with no lengths, so
//! one mis-sized form desynchronises the whole CU and every later name is
//! garbage. `skip_form` therefore covers the full DWARF 2-5 form set, and
//! anything it does not recognise ABORTS that CU rather than guessing — a
//! missing name is recoverable, a wrong one is not.
//!
//! Hand-rolled, bounds-checked, std-only; never panics on malformed input.

use crate::Symbol;

// tags
const DW_TAG_SUBPROGRAM: u64 = 0x2e;

// attributes
const DW_AT_NAME: u64 = 0x03;
const DW_AT_LOW_PC: u64 = 0x11;
const DW_AT_STR_OFFSETS_BASE: u64 = 0x72;

// forms
const F_ADDR: u64 = 0x01;
const F_BLOCK2: u64 = 0x03;
const F_BLOCK4: u64 = 0x04;
const F_DATA2: u64 = 0x05;
const F_DATA4: u64 = 0x06;
const F_DATA8: u64 = 0x07;
const F_STRING: u64 = 0x08;
const F_BLOCK: u64 = 0x09;
const F_BLOCK1: u64 = 0x0a;
const F_DATA1: u64 = 0x0b;
const F_FLAG: u64 = 0x0c;
const F_SDATA: u64 = 0x0d;
const F_STRP: u64 = 0x0e;
const F_UDATA: u64 = 0x0f;
const F_REF_ADDR: u64 = 0x10;
const F_REF1: u64 = 0x11;
const F_REF2: u64 = 0x12;
const F_REF4: u64 = 0x13;
const F_REF8: u64 = 0x14;
const F_REF_UDATA: u64 = 0x15;
const F_INDIRECT: u64 = 0x16;
const F_SEC_OFFSET: u64 = 0x17;
const F_EXPRLOC: u64 = 0x18;
const F_FLAG_PRESENT: u64 = 0x19;
const F_STRX: u64 = 0x1a;
const F_ADDRX: u64 = 0x1b;
const F_REF_SUP4: u64 = 0x1c;
const F_STRP_SUP: u64 = 0x1d;
const F_DATA16: u64 = 0x1e;
const F_LINE_STRP: u64 = 0x1f;
const F_REF_SIG8: u64 = 0x20;
const F_IMPLICIT_CONST: u64 = 0x21;
const F_LOCLISTX: u64 = 0x22;
const F_RNGLISTX: u64 = 0x23;
const F_REF_SUP8: u64 = 0x24;
const F_STRX1: u64 = 0x25;
const F_STRX2: u64 = 0x26;
const F_STRX3: u64 = 0x27;
const F_STRX4: u64 = 0x28;
const F_ADDRX1: u64 = 0x29;
const F_ADDRX2: u64 = 0x2a;
const F_ADDRX3: u64 = 0x2b;
const F_ADDRX4: u64 = 0x2c;

/// The DWARF sections a caller must supply (empty slice when absent).
#[derive(Default, Clone, Copy)]
pub(crate) struct Sections<'a> {
    pub info: &'a [u8],
    pub abbrev: &'a [u8],
    pub str_: &'a [u8],
    pub line_str: &'a [u8],
    pub str_offsets: &'a [u8],
}

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cur { b, p: 0 }
    }
    fn left(&self) -> usize {
        self.b.len().saturating_sub(self.p)
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.p)?;
        self.p += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        let s = self.b.get(self.p..self.p.checked_add(2)?)?;
        self.p += 2;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        let s = self.b.get(self.p..self.p.checked_add(4)?)?;
        self.p += 4;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        let s = self.b.get(self.p..self.p.checked_add(8)?)?;
        self.p += 8;
        Some(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        if n > self.left() {
            return None;
        }
        self.p += n;
        Some(())
    }
    fn uleb(&mut self) -> Option<u64> {
        let (mut v, mut shift) = (0u64, 0u32);
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= u64::from(b & 0x7f) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                return Some(v);
            }
            if shift > 128 {
                return None; // malformed: refuse rather than spin
            }
        }
    }
    fn sleb(&mut self) -> Option<i64> {
        let (mut v, mut shift) = (0i64, 0u32);
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= i64::from(b & 0x7f) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    v |= -1i64 << shift;
                }
                return Some(v);
            }
            if shift > 128 {
                return None;
            }
        }
    }
    /// NUL-terminated string starting at the cursor.
    fn cstr(&mut self) -> Option<String> {
        let start = self.p;
        while self.p < self.b.len() && self.b[self.p] != 0 {
            self.p += 1;
        }
        let s = String::from_utf8_lossy(self.b.get(start..self.p)?).into_owned();
        self.p = self.p.saturating_add(1); // consume the NUL
        Some(s)
    }
}

fn str_at(sec: &[u8], off: usize) -> Option<String> {
    let end = sec.get(off..)?.iter().position(|&c| c == 0).unwrap_or(0);
    Some(String::from_utf8_lossy(sec.get(off..off + end)?).into_owned())
}

/// One abbreviation: tag + whether it has children + its (attr, form, implicit) list.
struct Abbrev {
    tag: u64,
    has_children: bool,
    attrs: Vec<(u64, u64, i64)>,
}

/// Parse the abbreviation table that starts at `off`.
fn parse_abbrev(sec: &[u8], off: usize) -> Option<std::collections::HashMap<u64, Abbrev>> {
    let mut c = Cur::new(sec.get(off..)?);
    let mut out = std::collections::HashMap::new();
    loop {
        let code = c.uleb()?;
        if code == 0 {
            return Some(out); // end of table
        }
        let tag = c.uleb()?;
        let has_children = c.u8()? != 0;
        let mut attrs = Vec::new();
        loop {
            let at = c.uleb()?;
            let form = c.uleb()?;
            // DW_FORM_implicit_const stores its value in the ABBREV, not the DIE.
            let ic = if form == F_IMPLICIT_CONST { c.sleb()? } else { 0 };
            if at == 0 && form == 0 {
                break;
            }
            attrs.push((at, form, ic));
        }
        out.insert(code, Abbrev { tag, has_children, attrs });
        if out.len() > 200_000 {
            return None; // implausible; treat as corrupt
        }
    }
}

/// Advance past one attribute value. Returns None for an unknown form, which the
/// caller treats as "abandon this CU" — a desynchronised walk invents names.
fn skip_form(c: &mut Cur, form: u64, addr_size: u8, off_size: u8) -> Option<()> {
    match form {
        F_ADDR => c.skip(addr_size as usize),
        F_BLOCK1 => {
            let n = c.u8()? as usize;
            c.skip(n)
        }
        F_BLOCK2 => {
            let n = c.u16()? as usize;
            c.skip(n)
        }
        F_BLOCK4 => {
            let n = c.u32()? as usize;
            c.skip(n)
        }
        F_BLOCK | F_EXPRLOC => {
            let n = c.uleb()? as usize;
            c.skip(n)
        }
        F_DATA1 | F_FLAG | F_REF1 | F_STRX1 | F_ADDRX1 => c.skip(1),
        F_DATA2 | F_REF2 | F_STRX2 | F_ADDRX2 => c.skip(2),
        F_STRX3 | F_ADDRX3 => c.skip(3),
        F_DATA4 | F_REF4 | F_REF_SUP4 | F_STRX4 | F_ADDRX4 => c.skip(4),
        F_DATA8 | F_REF8 | F_REF_SIG8 | F_REF_SUP8 => c.skip(8),
        F_DATA16 => c.skip(16),
        F_SDATA => c.sleb().map(|_| ()),
        F_UDATA | F_REF_UDATA | F_STRX | F_ADDRX | F_LOCLISTX | F_RNGLISTX => {
            c.uleb().map(|_| ())
        }
        F_STRING => c.cstr().map(|_| ()),
        F_STRP | F_LINE_STRP | F_SEC_OFFSET | F_STRP_SUP | F_REF_ADDR => {
            c.skip(off_size as usize)
        }
        F_FLAG_PRESENT | F_IMPLICIT_CONST => Some(()), // occupy no bytes in the DIE
        F_INDIRECT => {
            let real = c.uleb()?;
            skip_form(c, real, addr_size, off_size)
        }
        _ => None,
    }
}

/// Recover `DW_TAG_subprogram` names + addresses. `vaddr_to_rva` maps a DWARF
/// address (a link-time virtual address) to the pipeline's rva space.
pub(crate) fn functions(secs: Sections, vaddr_to_rva: impl Fn(u64) -> Option<u64>) -> Vec<Symbol> {
    let mut out: Vec<Symbol> = Vec::new();
    if secs.info.is_empty() || secs.abbrev.is_empty() {
        return out;
    }
    let mut cu_start = 0usize;
    // Bound the CU count so a corrupt length field cannot spin forever.
    for _ in 0..100_000 {
        if cu_start.saturating_add(11) > secs.info.len() {
            break;
        }
        let mut c = Cur::new(&secs.info[cu_start..]);
        // unit_length: 0xffffffff introduces the 64-bit DWARF format.
        let mut off_size = 4u8;
        let mut unit_len = match c.u32() {
            Some(v) => u64::from(v),
            None => break,
        };
        if unit_len == 0xffff_ffff {
            off_size = 8;
            unit_len = match c.u64() {
                Some(v) => v,
                None => break,
            };
        } else if unit_len >= 0xffff_fff0 {
            break; // reserved
        }
        let after_len = c.p;
        let next_cu = cu_start.saturating_add(after_len).saturating_add(unit_len as usize);
        if unit_len == 0 || next_cu <= cu_start || next_cu > secs.info.len() {
            break;
        }
        let version = match c.u16() {
            Some(v) => v,
            None => break,
        };
        let (abbrev_off, addr_size) = if version >= 5 {
            let _unit_type = c.u8();
            let a = c.u8().unwrap_or(8);
            let ao = if off_size == 8 { c.u64() } else { c.u32().map(u64::from) };
            (ao.unwrap_or(0), a)
        } else {
            let ao = if off_size == 8 { c.u64() } else { c.u32().map(u64::from) };
            let a = c.u8().unwrap_or(8);
            (ao.unwrap_or(0), a)
        };
        if version == 0 || version > 5 {
            cu_start = next_cu;
            continue;
        }

        let table = match parse_abbrev(secs.abbrev, abbrev_off as usize) {
            Some(t) => t,
            None => {
                cu_start = next_cu;
                continue;
            }
        };

        // DWARF 5 str_offsets_base; the header is 8 bytes, so that is the default.
        let mut str_off_base = 8usize;
        let mut pending: Vec<(String, u64)> = Vec::new();

        // Walk the DIEs of this CU.
        let cu_end = next_cu - cu_start;
        let mut guard = 0u32;
        while c.p < cu_end {
            guard += 1;
            if guard > 2_000_000 {
                break;
            }
            let code = match c.uleb() {
                Some(v) => v,
                None => break,
            };
            if code == 0 {
                continue; // end of a sibling chain
            }
            let ab = match table.get(&code) {
                Some(a) => a,
                None => break, // unknown abbrev: the walk is desynchronised
            };
            let _ = ab.has_children;
            let mut name: Option<String> = None;
            let mut low_pc: Option<u64> = None;
            let mut strx: Option<u64> = None;
            let mut bad = false;
            for &(at, form, _ic) in &ab.attrs {
                match (at, form) {
                    (DW_AT_NAME, F_STRING) => name = c.cstr(),
                    (DW_AT_NAME, F_STRP) => {
                        let o = if off_size == 8 { c.u64() } else { c.u32().map(u64::from) };
                        name = o.and_then(|o| str_at(secs.str_, o as usize));
                    }
                    (DW_AT_NAME, F_LINE_STRP) => {
                        let o = if off_size == 8 { c.u64() } else { c.u32().map(u64::from) };
                        name = o.and_then(|o| str_at(secs.line_str, o as usize));
                    }
                    (DW_AT_NAME, F_STRX) => strx = c.uleb(),
                    (DW_AT_NAME, F_STRX1) => strx = c.u8().map(u64::from),
                    (DW_AT_NAME, F_STRX2) => strx = c.u16().map(u64::from),
                    (DW_AT_NAME, F_STRX4) => strx = c.u32().map(u64::from),
                    (DW_AT_LOW_PC, F_ADDR) => {
                        low_pc = if addr_size == 8 { c.u64() } else { c.u32().map(u64::from) };
                    }
                    (DW_AT_STR_OFFSETS_BASE, _) => {
                        let o = if off_size == 8 { c.u64() } else { c.u32().map(u64::from) };
                        if let Some(o) = o {
                            str_off_base = o as usize;
                        }
                    }
                    _ => {
                        if skip_form(&mut c, form, addr_size, off_size).is_none() {
                            bad = true;
                            break;
                        }
                    }
                }
            }
            if bad {
                break;
            }
            if ab.tag == DW_TAG_SUBPROGRAM {
                if let Some(pc) = low_pc {
                    if let Some(n) = name {
                        if !n.is_empty() {
                            pending.push((n, pc));
                        }
                    } else if let Some(ix) = strx {
                        // resolve later: str_offsets_base may appear after this DIE
                        let slot = str_off_base + (ix as usize) * (off_size as usize);
                        let o = match off_size {
                            8 => secs
                                .str_offsets
                                .get(slot..slot + 8)
                                .map(|s| u64::from_le_bytes(s.try_into().unwrap_or([0; 8]))),
                            _ => secs
                                .str_offsets
                                .get(slot..slot + 4)
                                .map(|s| u64::from(u32::from_le_bytes(s.try_into().unwrap_or([0; 4])))),
                        };
                        if let Some(n) = o.and_then(|o| str_at(secs.str_, o as usize)) {
                            if !n.is_empty() {
                                pending.push((n, pc));
                            }
                        }
                    }
                }
            }
        }

        for (n, pc) in pending {
            if let Some(rva) = vaddr_to_rva(pc) {
                out.push(Symbol { rva, name: n, module: None });
            }
        }
        cu_start = next_cu;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-built DWARF 4 CU with one DW_TAG_subprogram (name + low_pc).
    fn tiny_dwarf() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        // .debug_abbrev: code 1 = subprogram, DW_AT_name(strp), DW_AT_low_pc(addr)
        let mut ab = Vec::new();
        ab.push(1); // code
        ab.push(0x2e); // DW_TAG_subprogram
        ab.push(0); // no children
        ab.extend_from_slice(&[0x03, 0x0e]); // name, strp
        ab.extend_from_slice(&[0x11, 0x01]); // low_pc, addr
        ab.extend_from_slice(&[0x00, 0x00]); // end attrs
        ab.push(0); // end table

        let strs = b"\0my_function\0".to_vec();

        // .debug_info CU
        let mut die = Vec::new();
        die.push(1); // abbrev code
        die.extend_from_slice(&1u32.to_le_bytes()); // name -> offset 1 in .debug_str
        die.extend_from_slice(&0x4010u64.to_le_bytes()); // low_pc
        die.push(0); // end of children

        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_le_bytes()); // version
        body.extend_from_slice(&0u32.to_le_bytes()); // abbrev offset
        body.push(8); // address size
        body.extend_from_slice(&die);

        let mut info = Vec::new();
        info.extend_from_slice(&(body.len() as u32).to_le_bytes());
        info.extend_from_slice(&body);
        (info, ab, strs)
    }

    #[test]
    fn recovers_a_function_name() {
        let (info, ab, strs) = tiny_dwarf();
        let secs = Sections { info: &info, abbrev: &ab, str_: &strs, ..Default::default() };
        let fns = functions(secs, |v| Some(v - 0x4000));
        assert_eq!(fns.len(), 1, "expected one subprogram, got {fns:?}");
        assert_eq!(fns[0].name, "my_function");
        assert_eq!(fns[0].rva, 0x10);
    }

    #[test]
    fn truncation_never_panics() {
        let (info, ab, strs) = tiny_dwarf();
        for n in 0..info.len() {
            let secs =
                Sections { info: &info[..n], abbrev: &ab, str_: &strs, ..Default::default() };
            let _ = functions(secs, |v| Some(v));
        }
        for n in 0..ab.len() {
            let secs =
                Sections { info: &info, abbrev: &ab[..n], str_: &strs, ..Default::default() };
            let _ = functions(secs, |v| Some(v));
        }
    }

    #[test]
    fn unknown_form_aborts_instead_of_inventing() {
        let (mut info, mut ab, strs) = tiny_dwarf();
        // Corrupt the form byte of DW_AT_name to an unassigned form.
        for i in 0..ab.len() - 1 {
            if ab[i] == 0x03 && ab[i + 1] == 0x0e {
                ab[i + 1] = 0x7f; // not a real form
                break;
            }
        }
        info[0] = info[0]; // unchanged
        let secs = Sections { info: &info, abbrev: &ab, str_: &strs, ..Default::default() };
        let fns = functions(secs, |v| Some(v));
        assert!(fns.is_empty(), "an unknown form must yield no names, got {fns:?}");
    }
}
