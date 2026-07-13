//! binparser — hand-rolled PE/ELF binary parser for DisasmStudio.
//!
//! std-only, zero external dependencies, fully bounds-checked: every read goes
//! through the checked little-endian helpers in this module, so malformed input
//! yields `Err(String)` and never panics.
//!
//! Public API is the frozen contract; format-specific parsing lives in the
//! `pe` and `elf` submodules and is re-exported through [`BinaryMeta::parse`].

mod elf;
mod pe;

/// Target instruction-set architecture. Ordinals match the engine `ds_arch`
/// enum (X86=0, X64=1, Arm=2, Arm64=3); `Unknown` is mapped to X64 by callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    X64,
    Arm,
    Arm64,
    Unknown,
}

impl Arch {
    /// Ordinal for the engine `ds_arch` ABI. Unknown collapses to X64 (1).
    pub fn ds_ordinal(self) -> u32 {
        match self {
            Arch::X86 => 0,
            Arch::X64 => 1,
            Arch::Arm => 2,
            Arch::Arm64 => 3,
            Arch::Unknown => 1,
        }
    }
}

/// Container format of the parsed binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Pe32,
    Pe32Plus,
    Elf32,
    Elf64,
}

/// A named symbol at an RVA (relative to `BinaryMeta::base`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub rva: u64,
    pub name: String,
}

/// A loadable region of the image. `flags` uses R=1, W=2, X=4.
/// `rva`/`vsize` describe the virtual layout; `file_off`/`file_size` describe
/// the raw bytes inside the on-disk file used to populate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub name: String,
    pub rva: u64,
    pub vsize: u64,
    pub flags: u32,
    pub file_off: u64,
    pub file_size: u64,
}

/// Parsed metadata for a binary, plus the data needed to lay out a flat image.
#[derive(Debug, Clone)]
pub struct BinaryMeta {
    pub format: Format,
    pub arch: Arch,
    pub base: u64,
    pub entry: u64,
    pub is_dll: bool,
    pub image_size: u64,
    pub segments: Vec<Segment>,
    pub exports: Vec<Symbol>,
    pub imports: Vec<Symbol>,
    pub tls_callbacks: Vec<u64>,
}

/// Segment permission flag bits (also used by the engine ABI).
pub const FLAG_R: u32 = 1;
pub const FLAG_W: u32 = 2;
pub const FLAG_X: u32 = 4;

impl BinaryMeta {
    /// Parse a PE or ELF binary from its raw file bytes. Returns `Err` with a
    /// human-readable message on any malformed or unsupported input. Never
    /// panics regardless of how truncated or corrupt `bytes` is.
    pub fn parse(bytes: &[u8]) -> Result<BinaryMeta, String> {
        if bytes.starts_with(b"MZ") {
            pe::parse(bytes)
        } else if bytes.starts_with(&[0x7F, b'E', b'L', b'F']) {
            elf::parse(bytes)
        } else {
            Err("unrecognized binary format (expected PE 'MZ' or ELF magic)".to_string())
        }
    }

    /// Build a flat, RVA-addressed image from the file `bytes`.
    ///
    /// The result is a zero-filled `Vec` sized to cover every segment
    /// (`max(rva + vsize)`); each segment's raw bytes
    /// (`bytes[file_off .. file_off + file_size]`) are copied to offset `rva`.
    /// All ranges are clamped to their respective buffer bounds so the call is
    /// safe for any combination of segment table and file length.
    pub fn build_image(&self, bytes: &[u8]) -> Vec<u8> {
        // Total image size: highest covered virtual address.
        let mut total: u64 = self.image_size;
        for seg in &self.segments {
            let end = seg.rva.saturating_add(seg.vsize);
            if end > total {
                total = end;
            }
        }
        // Round up to a sane alignment so the engine can read past tails safely.
        let total = round_up(total, 0x1000);
        // Guard against absurd sizes from corrupt input.
        let cap = total.min(u64::from(u32::MAX) * 4) as usize;
        let mut image = vec![0u8; cap];

        for seg in &self.segments {
            let foff = seg.file_off as usize;
            let fsize = seg.file_size as usize;
            let voff = seg.rva as usize;
            let vsize = seg.vsize as usize;

            if foff >= bytes.len() {
                continue;
            }
            // How many raw bytes are actually available in the file.
            let avail_file = bytes.len() - foff;
            let mut copy = fsize.min(avail_file);
            // Never write past the segment's virtual size or the image buffer.
            copy = copy.min(vsize);
            if voff >= image.len() {
                continue;
            }
            copy = copy.min(image.len() - voff);
            if copy == 0 {
                continue;
            }
            image[voff..voff + copy].copy_from_slice(&bytes[foff..foff + copy]);
        }

        image
    }
}

/// Round `v` up to a multiple of `align` (must be a power of two), saturating.
pub(crate) fn round_up(v: u64, align: u64) -> u64 {
    if align == 0 {
        return v;
    }
    let mask = align - 1;
    v.saturating_add(mask) & !mask
}

// ---- checked little-endian readers ---------------------------------------
//
// Every multi-byte field in a parsed binary is read through one of these.
// They return `None` rather than indexing out of bounds, which propagates up
// to an `Err` at the parse boundary.

#[inline]
pub(crate) fn rd_u16(buf: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let s = buf.get(off..end)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
pub(crate) fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let s = buf.get(off..end)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
pub(crate) fn rd_u64(buf: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let s = buf.get(off..end)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

/// Read a NUL-terminated ASCII/UTF-8 string starting at `off`, scanning at most
/// `max` bytes. Lossy UTF-8 so arbitrary bytes never panic. Returns `None` only
/// if `off` is already out of bounds.
pub(crate) fn rd_cstr(buf: &[u8], off: usize, max: usize) -> Option<String> {
    if off >= buf.len() {
        return None;
    }
    let hard_end = off.saturating_add(max).min(buf.len());
    let mut end = off;
    while end < hard_end && buf[end] != 0 {
        end += 1;
    }
    Some(String::from_utf8_lossy(&buf[off..end]).into_owned())
}
