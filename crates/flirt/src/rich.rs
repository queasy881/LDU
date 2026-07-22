//! PE "Rich" header parsing — the XOR-obfuscated block MSVC's linker stamps
//! between the DOS stub and the PE header. It records `@comp.id` entries (a
//! product id + build number per tool that touched the object), which identify
//! the MSVC toolchain version so the right signature DB can be preferred.

/// Return the highest MSVC build number found in the Rich header, or None. Build
/// ranges map to toolsets: ~26xxx = VS2019, ~30xxx-31xxx = VS2022, ~36xxx = VS2026.
pub fn max_build(pe: &[u8]) -> Option<u16> {
    if pe.len() < 0x40 || &pe[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(pe.get(0x3c..0x40)?.try_into().ok()?) as usize;
    if e_lfanew < 0x40 || e_lfanew > pe.len() {
        return None;
    }
    // find "Rich" in [0x40, e_lfanew); the u32 after it is the XOR key
    let region = &pe[0x40..e_lfanew.min(pe.len())];
    let rich_pos = find(region, b"Rich")?;
    let key = u32::from_le_bytes(region.get(rich_pos + 4..rich_pos + 8)?.try_into().ok()?);
    // walk backwards in 8-byte records until the de-XORed "DanS" marker
    let mut best: u16 = 0;
    let mut off = rich_pos;
    while off >= 8 {
        off -= 8;
        let a = u32::from_le_bytes(region[off..off + 4].try_into().ok()?) ^ key;
        let b = u32::from_le_bytes(region[off + 4..off + 8].try_into().ok()?) ^ key;
        if a == 0x536e_6144 {
            // "DanS" — start of the records
            break;
        }
        // record: high 16 bits of `a` = build number, low 16 = product id; `b` = count
        let build = (a >> 16) as u16;
        let _count = b;
        if build > best {
            best = build;
        }
    }
    if best > 0 {
        Some(best)
    } else {
        None
    }
}

/// A coarse toolset label from a build number (best-effort; the matcher still
/// tries every DB, so this only prioritizes).
pub fn toolset_label(build: u16) -> &'static str {
    match build {
        0..=25999 => "msvc2017",
        26000..=27999 => "msvc2019",
        28000..=33999 => "msvc2022",
        _ => "msvc2026",
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}
