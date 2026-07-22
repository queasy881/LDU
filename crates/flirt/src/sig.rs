//! FLIRT-style function signatures + on-disk database + matcher.
//!
//! A signature is the function's leading bytes with linker-relocated bytes
//! wildcarded (`mask`), a CRC16 over the run of fixed bytes after the pattern,
//! the total function length, and the external symbols it references (used to
//! break ties between functions that share a prologue). This is deliberately a
//! self-contained format — NOT IDA's `.sig` binary — but the algorithm is the
//! same: pattern + CRC + length + referenced-name disambiguation.

pub const PATLEN: usize = 32;

/// One library function's signature.
#[derive(Clone, Debug)]
pub struct FuncSig {
    pub pat: [u8; PATLEN], // leading bytes (zero-padded if shorter)
    pub mask: u32,         // bit i set => pat[i] is a wildcard (relocated) byte
    pub plen: u8,          // number of valid pattern bytes (<= PATLEN)
    pub crc_len: u8,       // number of bytes after PATLEN covered by `crc`
    pub crc: u16,          // CRC16 of bytes [PATLEN .. PATLEN+crc_len)
    pub full_len: u32,     // total function byte length
    pub name: String,
    pub refs: Vec<(u16, String)>, // (offset, external symbol) for tie-breaking
}

/// CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF). Any consistent CRC works since
/// generation and matching share this function; CCITT is a proven-good mixer.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// Build a signature from a function's raw bytes and the set of byte offsets that
/// are relocated (variant). `refs` are (offset, name) pairs the caller resolved
/// from relocations to external symbols.
pub fn make_sig(name: &str, code: &[u8], variant: &[bool], refs: Vec<(u16, String)>) -> Option<FuncSig> {
    if code.len() < 6 {
        return None; // too short to signature safely (thunks collide)
    }
    let plen = code.len().min(PATLEN);
    let mut pat = [0u8; PATLEN];
    let mut mask = 0u32;
    for i in 0..plen {
        if variant.get(i).copied().unwrap_or(false) {
            mask |= 1 << i;
            pat[i] = 0; // wildcard; value irrelevant
        } else {
            pat[i] = code[i];
        }
    }
    // CRC region: the run of FIXED (non-variant) bytes starting at PATLEN, IDA-style.
    let mut crc_len = 0usize;
    if code.len() > PATLEN {
        while PATLEN + crc_len < code.len()
            && crc_len < 255
            && !variant.get(PATLEN + crc_len).copied().unwrap_or(false)
        {
            crc_len += 1;
        }
    }
    let crc = if crc_len > 0 {
        crc16(&code[PATLEN..PATLEN + crc_len])
    } else {
        0
    };
    Some(FuncSig {
        pat,
        mask,
        plen: plen as u8,
        crc_len: crc_len as u8,
        crc,
        full_len: code.len() as u32,
        name: name.to_string(),
        refs,
    })
}

/// A signature database: the functions plus a first-byte index for fast lookup.
pub struct SigDb {
    pub toolchain: String,
    pub sigs: Vec<FuncSig>,
    by_first: std::collections::HashMap<u8, Vec<usize>>, // pat[0] (when not wild) -> sig ids
    wild_first: Vec<usize>,                              // sigs whose byte 0 is wildcarded
}

impl SigDb {
    pub fn new(toolchain: String, sigs: Vec<FuncSig>) -> SigDb {
        let mut by_first: std::collections::HashMap<u8, Vec<usize>> = std::collections::HashMap::new();
        let mut wild_first = Vec::new();
        for (i, s) in sigs.iter().enumerate() {
            if s.mask & 1 != 0 {
                wild_first.push(i);
            } else {
                by_first.entry(s.pat[0]).or_default().push(i);
            }
        }
        SigDb { toolchain, sigs, by_first, wild_first }
    }

    /// Match a candidate function's bytes against the database. `known` maps an
    /// offset (of a call/ref site) to the name already assigned at that target,
    /// used only to disambiguate multiple pattern+CRC matches. Returns the name.
    pub fn match_fn<F: Fn(u16) -> Option<String>>(&self, code: &[u8], known: F) -> Option<&str> {
        if code.len() < 6 {
            return None;
        }
        // candidate set: sigs whose fixed first byte equals code[0], plus wild-first.
        let mut cands: Vec<usize> = Vec::new();
        if let Some(v) = self.by_first.get(&code[0]) {
            cands.extend_from_slice(v);
        }
        cands.extend_from_slice(&self.wild_first);
        let mut hits: Vec<usize> = Vec::new();
        for &i in &cands {
            if self.pat_crc_len_ok(&self.sigs[i], code) {
                hits.push(i);
            }
        }
        match hits.len() {
            0 => None,
            1 => Some(&self.sigs[hits[0]].name),
            _ => {
                // Tie-break by referenced names: the candidate whose refs match the
                // names already known at those offsets in the target wins.
                let mut best: Option<usize> = None;
                let mut best_score = -1i32;
                for &i in &hits {
                    let s = &self.sigs[i];
                    if s.refs.is_empty() {
                        continue;
                    }
                    let mut score = 0i32;
                    let mut bad = false;
                    for (off, nm) in &s.refs {
                        match known(*off) {
                            Some(k) if &k == nm => score += 1,
                            Some(_) => {
                                bad = true;
                                break;
                            }
                            None => {}
                        }
                    }
                    if !bad && score > best_score {
                        best_score = score;
                        best = Some(i);
                    }
                }
                best.map(|i| self.sigs[i].name.as_str())
            }
        }
    }

    fn pat_crc_len_ok(&self, s: &FuncSig, code: &[u8]) -> bool {
        // length: allow the candidate to be at least the sig length (the engine's
        // boundary may run long); require the sig's whole pattern+crc region present.
        let need = PATLEN + s.crc_len as usize;
        if (code.len() as u32) < s.full_len {
            // tolerate small over/undershoot only if the pattern+crc still fit
            if code.len() < need.min(s.full_len as usize) {
                return false;
            }
        }
        let plen = s.plen as usize;
        if code.len() < plen {
            return false;
        }
        for i in 0..plen {
            if s.mask & (1 << i) != 0 {
                continue; // wildcard
            }
            if code[i] != s.pat[i] {
                return false;
            }
        }
        // exact length is a strong check when it agrees
        if s.full_len != code.len() as u32 {
            // require the CRC region to still validate below; length mismatch alone
            // is not fatal (imperfect boundaries), but a wrong length + wrong crc is.
        }
        if s.crc_len > 0 {
            let end = PATLEN + s.crc_len as usize;
            if code.len() < end {
                return false;
            }
            if crc16(&code[PATLEN..end]) != s.crc {
                return false;
            }
        }
        true
    }
}

// ---- on-disk format: "FDB1" | u32 tc_len | tc | u32 count | records ----------
// record: u16 name_len | name | 32 pat | u32 mask | u8 plen | u8 crc_len | u16 crc
//         | u32 full_len | u16 nrefs | (u16 off | u16 rname_len | rname)*

pub fn serialize(db_toolchain: &str, sigs: &[FuncSig]) -> Vec<u8> {
    let mut o = Vec::with_capacity(sigs.len() * 64 + 32);
    o.extend_from_slice(b"FDB1");
    put_u32(&mut o, db_toolchain.len() as u32);
    o.extend_from_slice(db_toolchain.as_bytes());
    put_u32(&mut o, sigs.len() as u32);
    for s in sigs {
        put_u16(&mut o, s.name.len() as u16);
        o.extend_from_slice(s.name.as_bytes());
        o.extend_from_slice(&s.pat);
        put_u32(&mut o, s.mask);
        o.push(s.plen);
        o.push(s.crc_len);
        put_u16(&mut o, s.crc);
        put_u32(&mut o, s.full_len);
        put_u16(&mut o, s.refs.len() as u16);
        for (off, nm) in &s.refs {
            put_u16(&mut o, *off);
            put_u16(&mut o, nm.len() as u16);
            o.extend_from_slice(nm.as_bytes());
        }
    }
    o
}

pub fn deserialize(buf: &[u8]) -> Option<SigDb> {
    if buf.len() < 4 || &buf[0..4] != b"FDB1" {
        return None;
    }
    let mut p = 4usize;
    let tclen = get_u32(buf, &mut p)? as usize;
    let toolchain = String::from_utf8_lossy(buf.get(p..p + tclen)?).into_owned();
    p += tclen;
    let count = get_u32(buf, &mut p)? as usize;
    let mut sigs = Vec::with_capacity(count);
    for _ in 0..count {
        let nlen = get_u16(buf, &mut p)? as usize;
        let name = String::from_utf8_lossy(buf.get(p..p + nlen)?).into_owned();
        p += nlen;
        let mut pat = [0u8; PATLEN];
        pat.copy_from_slice(buf.get(p..p + PATLEN)?);
        p += PATLEN;
        let mask = get_u32(buf, &mut p)?;
        let plen = *buf.get(p)?;
        p += 1;
        let crc_len = *buf.get(p)?;
        p += 1;
        let crc = get_u16(buf, &mut p)?;
        let full_len = get_u32(buf, &mut p)?;
        let nrefs = get_u16(buf, &mut p)? as usize;
        let mut refs = Vec::with_capacity(nrefs);
        for _ in 0..nrefs {
            let off = get_u16(buf, &mut p)?;
            let rlen = get_u16(buf, &mut p)? as usize;
            let rn = String::from_utf8_lossy(buf.get(p..p + rlen)?).into_owned();
            p += rlen;
            refs.push((off, rn));
        }
        sigs.push(FuncSig { pat, mask, plen, crc_len, crc, full_len, name, refs });
    }
    Some(SigDb::new(toolchain, sigs))
}

fn put_u16(o: &mut Vec<u8>, v: u16) { o.extend_from_slice(&v.to_le_bytes()); }
fn put_u32(o: &mut Vec<u8>, v: u32) { o.extend_from_slice(&v.to_le_bytes()); }
fn get_u16(b: &[u8], p: &mut usize) -> Option<u16> { let v = u16::from_le_bytes(b.get(*p..*p + 2)?.try_into().ok()?); *p += 2; Some(v) }
fn get_u32(b: &[u8], p: &mut usize) -> Option<u32> { let v = u32::from_le_bytes(b.get(*p..*p + 4)?.try_into().ok()?); *p += 4; Some(v) }
