//! PE (Portable Executable) parser. Hand-rolled, bounds-checked, std-only.
//!
//! Handles PE32 and PE32+, the section table, and the export / import / TLS
//! data directories. All file access goes through the checked readers in the
//! crate root, so any truncation or corruption produces an `Err` instead of a
//! panic.

use crate::{
    rd_cstr, rd_u16, rd_u32, rd_u64, Arch, BinaryMeta, Format, Segment, Symbol, FLAG_R, FLAG_W,
    FLAG_X,
};

// COFF machine types.
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

// Characteristics.
const IMAGE_FILE_DLL: u16 = 0x2000;

// Optional header magics.
const MAGIC_PE32: u16 = 0x010b;
const MAGIC_PE32PLUS: u16 = 0x020b;

// Section characteristics.
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

// Data directory indices.
const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_TLS: usize = 9;

/// One entry of the optional-header data directory array.
#[derive(Clone, Copy, Default)]
struct DataDir {
    rva: u32,
    size: u32,
}

/// Everything we need from the headers to perform RVA→file translation and to
/// walk the data directories.
struct PeCtx {
    format: Format,
    arch: Arch,
    base: u64,
    entry: u64,
    is_dll: bool,
    image_size: u64,
    ptr_size: u64,
    dirs: Vec<DataDir>,
    segments: Vec<Segment>,
}

pub(crate) fn parse(bytes: &[u8]) -> Result<BinaryMeta, String> {
    // DOS header: e_magic 'MZ' already checked by the dispatcher; e_lfanew @ 0x3C.
    if rd_u16(bytes, 0).ok_or("truncated DOS header")? != 0x5A4D {
        return Err("missing MZ signature".to_string());
    }
    let e_lfanew = rd_u32(bytes, 0x3C).ok_or("truncated DOS header (e_lfanew)")? as usize;

    // PE signature "PE\0\0".
    let sig = rd_u32(bytes, e_lfanew).ok_or("PE header offset out of range")?;
    if sig != 0x0000_4550 {
        return Err("missing PE\\0\\0 signature".to_string());
    }

    // COFF file header (20 bytes) immediately after the 4-byte signature.
    let coff = e_lfanew + 4;
    let machine = rd_u16(bytes, coff).ok_or("truncated COFF header")?;
    let num_sections = rd_u16(bytes, coff + 2).ok_or("truncated COFF header")? as usize;
    let size_opt_hdr = rd_u16(bytes, coff + 16).ok_or("truncated COFF header")? as usize;
    let characteristics = rd_u16(bytes, coff + 18).ok_or("truncated COFF header")?;

    let arch = match machine {
        IMAGE_FILE_MACHINE_I386 => Arch::X86,
        IMAGE_FILE_MACHINE_AMD64 => Arch::X64,
        IMAGE_FILE_MACHINE_ARM | IMAGE_FILE_MACHINE_ARMNT => Arch::Arm,
        IMAGE_FILE_MACHINE_ARM64 => Arch::Arm64,
        _ => Arch::Unknown,
    };
    let is_dll = characteristics & IMAGE_FILE_DLL != 0;

    // Optional header begins right after the COFF header.
    let opt = coff + 20;
    let magic = rd_u16(bytes, opt).ok_or("truncated optional header")?;

    let (format, ptr_size, base, entry, image_size, num_dirs, dir_table_off) = match magic {
        MAGIC_PE32 => {
            // PE32 layout (offsets relative to `opt`):
            //  16 AddressOfEntryPoint(u32)
            //  28 ImageBase(u32)
            //  56 SizeOfImage(u32)
            //  92 NumberOfRvaAndSizes(u32); data dirs begin at 96.
            let entry_rva = rd_u32(bytes, opt + 16).ok_or("truncated optional header")? as u64;
            let image_base = rd_u32(bytes, opt + 28).ok_or("truncated optional header")? as u64;
            let size_image = rd_u32(bytes, opt + 56).ok_or("truncated optional header")? as u64;
            let n = rd_u32(bytes, opt + 92).ok_or("truncated optional header")? as usize;
            (Format::Pe32, 4u64, image_base, entry_rva, size_image, n, opt + 96)
        }
        MAGIC_PE32PLUS => {
            // PE32+ layout:
            //  16 AddressOfEntryPoint(u32)
            //  24 ImageBase(u64)
            //  56 SizeOfImage(u32)
            // 108 NumberOfRvaAndSizes(u32); data dirs begin at 112.
            let entry_rva = rd_u32(bytes, opt + 16).ok_or("truncated optional header")? as u64;
            let image_base = rd_u64(bytes, opt + 24).ok_or("truncated optional header")?;
            let size_image = rd_u32(bytes, opt + 56).ok_or("truncated optional header")? as u64;
            let n = rd_u32(bytes, opt + 108).ok_or("truncated optional header")? as usize;
            (
                Format::Pe32Plus,
                8u64,
                image_base,
                entry_rva,
                size_image,
                n,
                opt + 112,
            )
        }
        _ => return Err(format!("unsupported optional header magic {:#06x}", magic)),
    };

    // Read up to 16 data directories (cap defensively; real PEs have <= 16).
    let num_dirs = num_dirs.min(16);
    let mut dirs = vec![DataDir::default(); 16];
    for (i, slot) in dirs.iter_mut().enumerate().take(num_dirs) {
        let off = dir_table_off + i * 8;
        slot.rva = rd_u32(bytes, off).unwrap_or(0);
        slot.size = rd_u32(bytes, off + 4).unwrap_or(0);
    }

    // Section table begins right after the optional header.
    let sec_table = opt + size_opt_hdr;
    let mut segments: Vec<Segment> = Vec::with_capacity(num_sections);
    // Cap section count to a sane bound to avoid huge loops on corrupt input.
    let num_sections = num_sections.min(96);
    for i in 0..num_sections {
        let s = sec_table + i * 40;
        // Each section header is 40 bytes.
        let name_raw = match bytes.get(s..s + 8) {
            Some(n) => n,
            None => break,
        };
        let name = decode_section_name(name_raw);
        let vsize = rd_u32(bytes, s + 8).unwrap_or(0) as u64;
        let vaddr = rd_u32(bytes, s + 12).unwrap_or(0) as u64;
        let raw_size = rd_u32(bytes, s + 16).unwrap_or(0) as u64;
        let raw_ptr = rd_u32(bytes, s + 20).unwrap_or(0) as u64;
        let chars = rd_u32(bytes, s + 36).unwrap_or(0);

        let mut flags = 0u32;
        if chars & SCN_MEM_READ != 0 {
            flags |= FLAG_R;
        }
        if chars & SCN_MEM_WRITE != 0 {
            flags |= FLAG_W;
        }
        if chars & SCN_MEM_EXECUTE != 0 {
            flags |= FLAG_X;
        }
        // If a section has no explicit perms, assume readable (common for data).
        if flags == 0 {
            flags = FLAG_R;
        }

        // VirtualSize of 0 happens (object-ish PEs); fall back to raw size.
        let effective_vsize = if vsize == 0 { raw_size } else { vsize };

        segments.push(Segment {
            name,
            rva: vaddr,
            vsize: effective_vsize,
            flags,
            file_off: raw_ptr,
            file_size: raw_size,
        });
    }

    let mut image_size = image_size;
    if image_size == 0 {
        // Derive from sections if SizeOfImage was bogus.
        for seg in &segments {
            let end = seg.rva.saturating_add(seg.vsize);
            if end > image_size {
                image_size = end;
            }
        }
    }

    let ctx = PeCtx {
        format,
        arch,
        base,
        entry,
        is_dll,
        image_size,
        ptr_size,
        dirs,
        segments,
    };

    let exports = parse_exports(bytes, &ctx);
    let imports = parse_imports(bytes, &ctx);
    let tls_callbacks = parse_tls(bytes, &ctx);

    Ok(BinaryMeta {
        format: ctx.format,
        arch: ctx.arch,
        base: ctx.base,
        entry: ctx.entry,
        is_dll: ctx.is_dll,
        image_size: ctx.image_size,
        segments: ctx.segments,
        exports,
        imports,
        tls_callbacks,
    })
}

/// Decode an 8-byte PE section name (NUL-padded ASCII). `/NNN` long-name forms
/// referencing the string table are left as-is — rare in shipped images.
fn decode_section_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// Translate an RVA to a file offset using the section table. Returns `None`
/// when the RVA falls outside every section's raw range.
fn rva_to_off(ctx: &PeCtx, rva: u64) -> Option<usize> {
    for seg in &ctx.segments {
        // Use the larger of virtual/raw size so headers laid out before raw
        // data still resolve; clamp to raw size for the actual file mapping.
        let span = seg.vsize.max(seg.file_size);
        if rva >= seg.rva && rva < seg.rva.saturating_add(span) {
            let delta = rva - seg.rva;
            if delta < seg.file_size {
                return Some(seg.file_off.saturating_add(delta) as usize);
            }
            // Inside virtual span but past raw data (e.g. .bss tail): no file bytes.
            return None;
        }
    }
    None
}

/// Read a NUL-terminated string addressed by RVA.
fn read_str_rva(bytes: &[u8], ctx: &PeCtx, rva: u64) -> Option<String> {
    let off = rva_to_off(ctx, rva)?;
    rd_cstr(bytes, off, 4096)
}

// ---- export directory -----------------------------------------------------

fn parse_exports(bytes: &[u8], ctx: &PeCtx) -> Vec<Symbol> {
    let mut out = Vec::new();
    let dir = ctx.dirs[DIR_EXPORT];
    if dir.rva == 0 || dir.size == 0 {
        return out;
    }
    let base = match rva_to_off(ctx, dir.rva as u64) {
        Some(o) => o,
        None => return out,
    };

    // IMAGE_EXPORT_DIRECTORY:
    //  0x14 NumberOfFunctions(u32)
    //  0x18 NumberOfNames(u32)
    //  0x1C AddressOfFunctions(rva u32)   — the EAT
    //  0x20 AddressOfNames(rva u32)
    //  0x24 AddressOfNameOrdinals(rva u32)
    let num_funcs = match rd_u32(bytes, base + 0x14) {
        Some(v) => v as usize,
        None => return out,
    };
    let num_names = rd_u32(bytes, base + 0x18).unwrap_or(0) as usize;
    let eat_rva = rd_u32(bytes, base + 0x1C).unwrap_or(0) as u64;
    let names_rva = rd_u32(bytes, base + 0x20).unwrap_or(0) as u64;
    let ords_rva = rd_u32(bytes, base + 0x24).unwrap_or(0) as u64;

    let eat_off = rva_to_off(ctx, eat_rva);
    let names_off = rva_to_off(ctx, names_rva);
    let ords_off = rva_to_off(ctx, ords_rva);

    // Export directory's own [rva, rva+size) range: a function RVA inside it is
    // a forwarder string ("OTHERDLL.func"), which we skip.
    let fwd_lo = dir.rva as u64;
    let fwd_hi = fwd_lo.saturating_add(dir.size as u64);

    // Bound the loops defensively.
    let num_funcs = num_funcs.min(1_000_000);
    let num_names = num_names.min(1_000_000);

    // Map ordinal index -> name, via the parallel Names/NameOrdinals arrays.
    // ords[i] is the index into the EAT for names[i].
    if let (Some(neff), Some(noff)) = (names_off, ords_off) {
        for i in 0..num_names {
            let name_ptr = match rd_u32(bytes, neff + i * 4) {
                Some(v) => v as u64,
                None => break,
            };
            let ord = match rd_u16(bytes, noff + i * 2) {
                Some(v) => v as usize,
                None => break,
            };
            if ord >= num_funcs {
                continue;
            }
            let func_rva = match eat_off {
                Some(eo) => rd_u32(bytes, eo + ord * 4).unwrap_or(0) as u64,
                None => 0,
            };
            if func_rva == 0 {
                continue;
            }
            if func_rva >= fwd_lo && func_rva < fwd_hi {
                // Forwarder export — skip (no local code).
                continue;
            }
            if let Some(name) = read_str_rva(bytes, ctx, name_ptr) {
                if !name.is_empty() {
                    out.push(Symbol {
                        rva: func_rva,
                        name,
                        module: None,
                    });
                }
            }
        }
    }

    out
}

// ---- import directory -----------------------------------------------------

fn parse_imports(bytes: &[u8], ctx: &PeCtx) -> Vec<Symbol> {
    let mut out = Vec::new();
    let dir = ctx.dirs[DIR_IMPORT];
    if dir.rva == 0 {
        return out;
    }
    let mut desc_off = match rva_to_off(ctx, dir.rva as u64) {
        Some(o) => o,
        None => return out,
    };

    let ptr = ctx.ptr_size as usize;
    // IMAGE_IMPORT_DESCRIPTOR is 20 bytes:
    //  0x00 OriginalFirstThunk (ILT rva)
    //  0x0C Name (rva)
    //  0x10 FirstThunk (IAT rva)
    // Terminated by an all-zero descriptor.
    let max_dlls = 4096usize;
    for _ in 0..max_dlls {
        let ilt_rva = rd_u32(bytes, desc_off).unwrap_or(0) as u64;
        let name_rva = rd_u32(bytes, desc_off + 0x0C).unwrap_or(0) as u64;
        let iat_rva = rd_u32(bytes, desc_off + 0x10).unwrap_or(0) as u64;

        if ilt_rva == 0 && iat_rva == 0 {
            break; // null terminator descriptor
        }

        // DLL name for this descriptor (IMAGE_IMPORT_DESCRIPTOR.Name -> ASCII).
        // Attached to every import from this table so the UI can group by module.
        let dll = read_str_rva(bytes, ctx, name_rva).filter(|s| !s.is_empty());

        // Prefer the ILT (OriginalFirstThunk) for names since the IAT may be
        // bound (overwritten by addresses); fall back to the IAT.
        let thunk_table_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
        let mut thunk_off = match rva_to_off(ctx, thunk_table_rva) {
            Some(o) => o,
            None => {
                desc_off += 20;
                continue;
            }
        };

        let high_bit: u64 = if ptr == 8 { 1u64 << 63 } else { 1u64 << 31 };
        let max_thunks = 200_000usize;
        let mut i = 0usize;
        while i < max_thunks {
            let thunk = if ptr == 8 {
                match rd_u64(bytes, thunk_off) {
                    Some(v) => v,
                    None => break,
                }
            } else {
                match rd_u32(bytes, thunk_off) {
                    Some(v) => v as u64,
                    None => break,
                }
            };
            if thunk == 0 {
                break; // end of this DLL's thunk array
            }

            // The IAT slot this thunk resolves to: FirstThunk + i*ptr.
            let slot_rva = iat_rva.saturating_add((i as u64) * (ptr as u64));

            if thunk & high_bit != 0 {
                // Import by ordinal — no name in the file. Surface it anyway as
                // `Ordinal_<n>` so the import is visible and groupable by DLL
                // (matches how IDA/Ghidra show unnamed ordinal imports).
                let ord = thunk & 0xFFFF;
                out.push(Symbol {
                    rva: slot_rva,
                    name: format!("Ordinal_{ord}"),
                    module: dll.clone(),
                });
            } else {
                // Import by name: thunk is an RVA to IMAGE_IMPORT_BY_NAME
                // { u16 Hint; char Name[]; } — the name starts at +2.
                let hint_rva = thunk & !high_bit;
                if let Some(hint_off) = rva_to_off(ctx, hint_rva) {
                    if let Some(name) = rd_cstr(bytes, hint_off + 2, 4096) {
                        if !name.is_empty() {
                            out.push(Symbol {
                                rva: slot_rva,
                                name,
                                module: dll.clone(),
                            });
                        }
                    }
                }
            }

            thunk_off += ptr;
            i += 1;
        }

        desc_off += 20;
    }

    out
}

// ---- TLS directory --------------------------------------------------------

fn parse_tls(bytes: &[u8], ctx: &PeCtx) -> Vec<u64> {
    let mut out = Vec::new();
    let dir = ctx.dirs[DIR_TLS];
    if dir.rva == 0 || dir.size == 0 {
        return out;
    }
    let off = match rva_to_off(ctx, dir.rva as u64) {
        Some(o) => o,
        None => return out,
    };

    let ptr = ctx.ptr_size as usize;
    // IMAGE_TLS_DIRECTORY:
    //  PE32:  AddressOfCallBacks @ +0x0C (VA, u32)
    //  PE32+: AddressOfCallBacks @ +0x18 (VA, u64)
    let cb_field_off = if ptr == 8 { off + 0x18 } else { off + 0x0C };
    let callbacks_va = if ptr == 8 {
        rd_u64(bytes, cb_field_off).unwrap_or(0)
    } else {
        rd_u32(bytes, cb_field_off).unwrap_or(0) as u64
    };
    if callbacks_va == 0 {
        return out;
    }
    // AddressOfCallBacks is a VA; convert to RVA via image base.
    let callbacks_rva = callbacks_va.checked_sub(ctx.base).unwrap_or(callbacks_va);
    let mut cb_off = match rva_to_off(ctx, callbacks_rva) {
        Some(o) => o,
        None => return out,
    };

    // Null-terminated array of callback VAs.
    let max_cb = 4096usize;
    for _ in 0..max_cb {
        let va = if ptr == 8 {
            match rd_u64(bytes, cb_off) {
                Some(v) => v,
                None => break,
            }
        } else {
            match rd_u32(bytes, cb_off) {
                Some(v) => v as u64,
                None => break,
            }
        };
        if va == 0 {
            break;
        }
        let rva = va.checked_sub(ctx.base).unwrap_or(va);
        out.push(rva);
        cb_off += ptr;
    }

    out
}
