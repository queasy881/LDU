//! Mach-O parser. Hand-rolled, bounds-checked, std-only.
//!
//! Reads the mach header, `LC_SEGMENT`/`LC_SEGMENT_64` load commands (for
//! segments), `LC_SYMTAB` (for function symbols) and `LC_MAIN`/`LC_UNIXTHREAD`
//! (for the entry point). Every read is checked; a truncated or hostile file
//! yields `Err`, never a panic.
//!
//! RVAs are relative to the FIRST mapped segment's `vmaddr`, which is what the
//! rest of the pipeline means by `base` — matching how the PE and ELF parsers
//! report it, so the engine's rva arithmetic is format-independent.
//!
//! A universal ("fat") binary is a container of several real Mach-Os. Rather
//! than fail on one, the best-matching slice is selected and parsed: x86-64
//! first, then arm64, else the first slice. Fat headers are BIG-endian even
//! though every slice inside is little-endian on the architectures we decompile.

use crate::{rd_cstr, Arch, BinaryMeta, Format, Segment, Symbol, FLAG_R, FLAG_W, FLAG_X};

pub(crate) const MH_MAGIC_64: u32 = 0xfeed_facf;
pub(crate) const MH_CIGAM_64: u32 = 0xcffa_edfe;
pub(crate) const MH_MAGIC_32: u32 = 0xfeed_face;
pub(crate) const MH_CIGAM_32: u32 = 0xcefa_edfe;
pub(crate) const FAT_MAGIC: u32 = 0xcafe_babe;
pub(crate) const FAT_CIGAM: u32 = 0xbeba_feca;

// filetype
const MH_EXECUTE: u32 = 2;
const MH_DYLIB: u32 = 6;
const MH_BUNDLE: u32 = 8;

// load commands
const LC_SEGMENT: u32 = 0x01;
const LC_SYMTAB: u32 = 0x02;
const LC_UNIXTHREAD: u32 = 0x05;
const LC_SEGMENT_64: u32 = 0x19;
const LC_MAIN: u32 = 0x8000_0028;

// cputype
const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM: u32 = 12;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;

// nlist n_type
const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0x0e;

// vm_prot
const VM_PROT_READ: u32 = 1;
const VM_PROT_WRITE: u32 = 2;
const VM_PROT_EXECUTE: u32 = 4;

struct Rdr<'a> {
    b: &'a [u8],
    le: bool,
}

impl<'a> Rdr<'a> {
    fn u32(&self, off: usize) -> Option<u32> {
        let s = self.b.get(off..off.checked_add(4)?)?;
        let a = [s[0], s[1], s[2], s[3]];
        Some(if self.le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) })
    }
    fn u64(&self, off: usize) -> Option<u64> {
        let s = self.b.get(off..off.checked_add(8)?)?;
        let a = [s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]];
        Some(if self.le { u64::from_le_bytes(a) } else { u64::from_be_bytes(a) })
    }
}

/// True when `bytes` opens with any Mach-O or fat magic.
pub(crate) fn is_macho(bytes: &[u8]) -> bool {
    let m = match bytes.get(0..4) {
        Some(s) => u32::from_be_bytes([s[0], s[1], s[2], s[3]]),
        None => return false,
    };
    let le = match bytes.get(0..4) {
        Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        None => return false,
    };
    matches!(m, FAT_MAGIC | FAT_CIGAM)
        || matches!(le, MH_MAGIC_64 | MH_CIGAM_64 | MH_MAGIC_32 | MH_CIGAM_32)
}

/// Pick the slice of a fat binary to decompile, returning its file range.
fn select_fat_slice(bytes: &[u8]) -> Result<(usize, usize), String> {
    // The fat header is always big-endian.
    let r = Rdr { b: bytes, le: false };
    let nfat = r.u32(4).ok_or("truncated fat header")? as usize;
    if nfat == 0 || nfat > 64 {
        return Err(format!("implausible fat arch count {nfat}"));
    }
    let mut best: Option<(usize, usize)> = None;
    let mut first: Option<(usize, usize)> = None;
    for i in 0..nfat {
        let e = 8 + i * 20; // fat_arch: cputype, cpusubtype, offset, size, align
        let cputype = r.u32(e).ok_or("truncated fat arch")?;
        let off = r.u32(e + 8).ok_or("truncated fat arch")? as usize;
        let size = r.u32(e + 12).ok_or("truncated fat arch")? as usize;
        if off.saturating_add(size) > bytes.len() {
            continue; // a slice that does not fit the file is not usable
        }
        first.get_or_insert((off, size));
        let rank = match cputype {
            CPU_TYPE_X86_64 => 2,
            CPU_TYPE_ARM64 => 1,
            _ => 0,
        };
        if rank > 0 && (best.is_none() || rank == 2) {
            best = Some((off, size));
            if rank == 2 {
                break;
            }
        }
    }
    best.or(first).ok_or_else(|| "no usable slice in fat binary".to_string())
}

pub(crate) fn parse(bytes: &[u8]) -> Result<BinaryMeta, String> {
    // Unwrap a universal binary to the slice we actually decompile. Offsets below
    // are relative to the slice, and `build_image` copies from the same slice, so
    // the caller never has to know.
    let head = bytes.get(0..4).ok_or("truncated Mach-O")?;
    let be_magic = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let (slice_off, _slice_len) = if matches!(be_magic, FAT_MAGIC | FAT_CIGAM) {
        select_fat_slice(bytes)?
    } else {
        (0usize, bytes.len())
    };
    let b = bytes.get(slice_off..).ok_or("fat slice out of range")?;

    let raw = b.get(0..4).ok_or("truncated mach header")?;
    let magic_le = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    // A CIGAM magic means the file's byte order is the opposite of ours.
    let (is64, le) = match magic_le {
        MH_MAGIC_64 => (true, true),
        MH_CIGAM_64 => (true, false),
        MH_MAGIC_32 => (false, true),
        MH_CIGAM_32 => (false, false),
        _ => return Err("not a Mach-O (bad magic)".to_string()),
    };
    let r = Rdr { b, le };

    let cputype = r.u32(4).ok_or("truncated mach header")?;
    let filetype = r.u32(12).ok_or("truncated mach header")?;
    let ncmds = r.u32(16).ok_or("truncated mach header")? as usize;
    let sizeofcmds = r.u32(20).ok_or("truncated mach header")? as usize;
    let hdr_len: usize = if is64 { 32 } else { 28 };
    if ncmds > 0x4000 {
        return Err(format!("implausible ncmds {ncmds}"));
    }

    let arch = match cputype {
        CPU_TYPE_X86_64 => Arch::X64,
        CPU_TYPE_X86 => Arch::X86,
        CPU_TYPE_ARM64 => Arch::Arm64,
        CPU_TYPE_ARM => Arch::Arm,
        _ => Arch::Unknown,
    };
    // A dylib/bundle is the Mach-O analogue of a DLL: no `start`, entry named per
    // the loader's view rather than as a program entry point.
    let is_dll = matches!(filetype, MH_DYLIB | MH_BUNDLE);

    let mut segments: Vec<Segment> = Vec::new();
    let mut base: Option<u64> = None;
    let mut entry_file_off: Option<u64> = None; // LC_MAIN gives a FILE offset
    let mut entry_abs: Option<u64> = None; // LC_UNIXTHREAD gives an ADDRESS
    let mut symtab: Option<(u64, u64, u64, u64)> = None;

    let mut off = hdr_len;
    let cmds_end = hdr_len.saturating_add(sizeofcmds).min(b.len());
    for _ in 0..ncmds {
        if off.saturating_add(8) > cmds_end {
            break;
        }
        let cmd = r.u32(off).ok_or("truncated load command")?;
        let cmdsize = r.u32(off + 4).ok_or("truncated load command")? as usize;
        // A zero/misaligned cmdsize would loop forever or walk backwards.
        if cmdsize < 8 || off.saturating_add(cmdsize) > cmds_end {
            break;
        }
        match cmd {
            LC_SEGMENT_64 | LC_SEGMENT => {
                let seg64 = cmd == LC_SEGMENT_64;
                let name = rd_cstr(b, off + 8, 16).unwrap_or_default();
                let (vmaddr, vmsize, fileoff, filesize, maxprot_off) = if seg64 {
                    (
                        r.u64(off + 24).ok_or("truncated LC_SEGMENT_64")?,
                        r.u64(off + 32).ok_or("truncated LC_SEGMENT_64")?,
                        r.u64(off + 40).ok_or("truncated LC_SEGMENT_64")?,
                        r.u64(off + 48).ok_or("truncated LC_SEGMENT_64")?,
                        off + 56,
                    )
                } else {
                    (
                        u64::from(r.u32(off + 24).ok_or("truncated LC_SEGMENT")?),
                        u64::from(r.u32(off + 28).ok_or("truncated LC_SEGMENT")?),
                        u64::from(r.u32(off + 32).ok_or("truncated LC_SEGMENT")?),
                        u64::from(r.u32(off + 36).ok_or("truncated LC_SEGMENT")?),
                        off + 40,
                    )
                };
                let initprot = r.u32(maxprot_off + 4).unwrap_or(VM_PROT_READ);
                // __PAGEZERO is a guard mapping with no protections and no contents;
                // treating it as the base would put every rva off by 4GB.
                if name == "__PAGEZERO" || (vmsize == 0 && filesize == 0) {
                    off += cmdsize;
                    continue;
                }
                if base.is_none() {
                    base = Some(vmaddr);
                }
                let mut flags = 0u32;
                if initprot & VM_PROT_READ != 0 {
                    flags |= FLAG_R;
                }
                if initprot & VM_PROT_WRITE != 0 {
                    flags |= FLAG_W;
                }
                if initprot & VM_PROT_EXECUTE != 0 {
                    flags |= FLAG_X;
                }
                segments.push(Segment {
                    name,
                    rva: vmaddr, // rebased below, once `base` is final
                    vsize: vmsize,
                    flags,
                    file_off: fileoff.saturating_add(slice_off as u64),
                    file_size: filesize,
                });
            }
            LC_SYMTAB => {
                let symoff = u64::from(r.u32(off + 8).ok_or("truncated LC_SYMTAB")?);
                let nsyms = u64::from(r.u32(off + 12).ok_or("truncated LC_SYMTAB")?);
                let stroff = u64::from(r.u32(off + 16).ok_or("truncated LC_SYMTAB")?);
                let strsize = u64::from(r.u32(off + 20).ok_or("truncated LC_SYMTAB")?);
                symtab = Some((symoff, nsyms, stroff, strsize));
            }
            LC_MAIN => {
                entry_file_off = r.u64(off + 8);
            }
            LC_UNIXTHREAD => {
                // The register state blob differs per arch; the PC sits at a known
                // slot. Only the two we can decompile are decoded.
                match cputype {
                    CPU_TYPE_X86_64 => entry_abs = r.u64(off + 16 + 16 * 8), // rip
                    CPU_TYPE_ARM64 => entry_abs = r.u64(off + 16 + 32 * 8),  // pc
                    _ => {}
                }
            }
            _ => {}
        }
        off += cmdsize;
    }

    let base = base.ok_or("Mach-O has no mapped segment")?;
    if segments.is_empty() {
        return Err("Mach-O has no loadable segments".to_string());
    }
    // Rebase to rva now that the first segment's vmaddr is known.
    let mut image_size = 0u64;
    for s in &mut segments {
        s.rva = s.rva.saturating_sub(base);
        image_size = image_size.max(s.rva.saturating_add(s.vsize));
    }

    // LC_MAIN's entryoff is a file offset; map it through the segment that covers
    // it. LC_UNIXTHREAD already gives an address.
    let entry = if let Some(fo) = entry_file_off {
        let fo = fo.saturating_add(slice_off as u64);
        segments
            .iter()
            .find(|s| fo >= s.file_off && fo < s.file_off.saturating_add(s.file_size))
            .map(|s| s.rva + (fo - s.file_off))
            .unwrap_or(0)
    } else {
        entry_abs.map(|a| a.saturating_sub(base)).unwrap_or(0)
    };

    // Function symbols from LC_SYMTAB. Defined-in-a-section externals only: an
    // undefined symbol has no address here, and a debug (STAB) entry is not code.
    let mut exports: Vec<Symbol> = Vec::new();
    if let Some((symoff, nsyms, stroff, strsize)) = symtab {
        let nlist = if is64 { 16usize } else { 12usize };
        let strs = {
            let a = (stroff as usize).min(b.len());
            let z = (stroff.saturating_add(strsize) as usize).min(b.len());
            b.get(a..z).unwrap_or(&[])
        };
        let cap = nsyms.min(2_000_000) as usize;
        for i in 0..cap {
            let e = (symoff as usize).saturating_add(i.saturating_mul(nlist));
            if e.saturating_add(nlist) > b.len() {
                break;
            }
            let n_strx = r.u32(e).unwrap_or(0) as usize;
            let n_type = *b.get(e + 4).unwrap_or(&0);
            let value = if is64 {
                r.u64(e + 8).unwrap_or(0)
            } else {
                u64::from(r.u32(e + 8).unwrap_or(0))
            };
            if n_type & N_STAB != 0 || n_type & N_TYPE != N_SECT || value == 0 {
                continue;
            }
            let name = match rd_cstr(strs, n_strx, 1024) {
                Some(n) if !n.is_empty() => n,
                _ => continue,
            };
            // Mach-O prefixes C symbols with '_'; strip it so names match what the
            // rest of the pipeline (and the user) expects.
            let name = name.strip_prefix('_').unwrap_or(&name).to_string();
            exports.push(Symbol { rva: value.saturating_sub(base), name, module: None });
        }
    }

    Ok(BinaryMeta {
        format: if is64 { Format::MachO64 } else { Format::MachO32 },
        arch,
        base,
        entry,
        is_dll,
        image_size,
        segments,
        exports,
        imports: Vec::new(),
        tls_callbacks: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal 64-bit Mach-O: header + one __TEXT segment + LC_MAIN.
    fn tiny_macho() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        v.extend_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
        v.extend_from_slice(&MH_EXECUTE.to_le_bytes());
        v.extend_from_slice(&2u32.to_le_bytes()); // ncmds
        v.extend_from_slice(&(72u32 + 24).to_le_bytes()); // sizeofcmds
        v.extend_from_slice(&0u32.to_le_bytes()); // flags
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved

        // LC_SEGMENT_64 __TEXT
        v.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        v.extend_from_slice(&72u32.to_le_bytes()); // cmdsize
        let mut nm = [0u8; 16];
        nm[..6].copy_from_slice(b"__TEXT");
        v.extend_from_slice(&nm);
        v.extend_from_slice(&0x1_0000_0000u64.to_le_bytes()); // vmaddr
        v.extend_from_slice(&0x1000u64.to_le_bytes()); // vmsize
        v.extend_from_slice(&0u64.to_le_bytes()); // fileoff
        v.extend_from_slice(&0x200u64.to_le_bytes()); // filesize
        v.extend_from_slice(&7u32.to_le_bytes()); // maxprot rwx
        v.extend_from_slice(&5u32.to_le_bytes()); // initprot r-x
        v.extend_from_slice(&0u32.to_le_bytes()); // nsects
        v.extend_from_slice(&0u32.to_le_bytes()); // flags

        // LC_MAIN
        v.extend_from_slice(&LC_MAIN.to_le_bytes());
        v.extend_from_slice(&24u32.to_le_bytes());
        v.extend_from_slice(&0x100u64.to_le_bytes()); // entryoff (file)
        v.extend_from_slice(&0u64.to_le_bytes()); // stacksize
        v.resize(0x400, 0);
        v
    }

    #[test]
    fn parses_minimal_macho() {
        let b = tiny_macho();
        assert!(is_macho(&b));
        let m = parse(&b).expect("parse");
        assert_eq!(m.format, Format::MachO64);
        assert_eq!(m.arch, Arch::X64);
        assert_eq!(m.base, 0x1_0000_0000);
        assert_eq!(m.segments.len(), 1);
        assert_eq!(m.segments[0].name, "__TEXT");
        assert_eq!(m.segments[0].rva, 0); // rebased off vmaddr
        assert_eq!(m.entry, 0x100); // LC_MAIN file offset mapped through __TEXT
        assert!(!m.is_dll);
    }

    #[test]
    fn truncation_never_panics() {
        let full = tiny_macho();
        for n in 0..full.len().min(400) {
            let _ = parse(&full[..n]); // must return Err, not panic
        }
    }

    #[test]
    fn pagezero_is_not_the_base() {
        // __PAGEZERO first, then __TEXT: the base must be __TEXT's vmaddr.
        let mut v = Vec::new();
        v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        v.extend_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&MH_EXECUTE.to_le_bytes());
        v.extend_from_slice(&2u32.to_le_bytes());
        v.extend_from_slice(&144u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        for (name, vmaddr, vmsize) in
            [(&b"__PAGEZERO"[..], 0u64, 0x1_0000_0000u64), (&b"__TEXT"[..], 0x1_0000_0000, 0x1000)]
        {
            v.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
            v.extend_from_slice(&72u32.to_le_bytes());
            let mut nm = [0u8; 16];
            nm[..name.len()].copy_from_slice(name);
            v.extend_from_slice(&nm);
            v.extend_from_slice(&vmaddr.to_le_bytes());
            v.extend_from_slice(&vmsize.to_le_bytes());
            v.extend_from_slice(&0u64.to_le_bytes());
            v.extend_from_slice(&0x200u64.to_le_bytes());
            v.extend_from_slice(&7u32.to_le_bytes());
            v.extend_from_slice(&5u32.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
        }
        v.resize(0x400, 0);
        let m = parse(&v).expect("parse");
        assert_eq!(m.base, 0x1_0000_0000, "__PAGEZERO must not become the base");
    }
}
