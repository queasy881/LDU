//! flirtmatch <db.fdb> <pe-file> — brute-scan a PE's executable sections for
//! library-function signature matches. A validation/diagnostic tool: it needs no
//! function list, so it proves the matcher end-to-end on a real binary.

use std::collections::BTreeSet;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: flirtmatch <db.fdb> <pe-file>");
        std::process::exit(2);
    }
    let db = match std::fs::read(&args[1]).ok().and_then(|b| flirt::deserialize(&b)) {
        Some(d) => d,
        None => {
            eprintln!("flirtmatch: bad db {}", args[1]);
            std::process::exit(1);
        }
    };
    let pe = std::fs::read(&args[2]).expect("read pe");
    let secs = exec_sections(&pe);
    if secs.is_empty() {
        eprintln!("flirtmatch: no executable section found");
        std::process::exit(1);
    }
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut hits = 0usize;
    for (start, size) in secs {
        let text = &pe[start..(start + size).min(pe.len())];
        // scan 4-byte-aligned offsets (function starts are aligned in practice)
        let mut i = 0usize;
        while i + 32 < text.len() {
            let win = &text[i..(i + 4096).min(text.len())];
            if let Some(nm) = db.match_fn(win, |_| None) {
                names.insert(nm.to_string());
                hits += 1;
                i += 16;
            } else {
                i += 4;
            }
        }
    }
    println!("flirtmatch: {} hits, {} distinct library functions named", hits, names.len());
    // print a sample, preferring recognizable C names
    let mut shown = 0;
    for n in &names {
        if shown >= 40 {
            break;
        }
        println!("  {n}");
        shown += 1;
    }
}

/// Return (file_offset, raw_size) of each executable PE section.
fn exec_sections(pe: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    if pe.len() < 0x40 || &pe[0..2] != b"MZ" {
        return out;
    }
    let e_lfanew = u32::from_le_bytes(pe[0x3c..0x40].try_into().unwrap()) as usize;
    if e_lfanew + 24 > pe.len() || &pe[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return out;
    }
    let coff = e_lfanew + 4;
    let num_sec = u16::from_le_bytes(pe[coff + 2..coff + 4].try_into().unwrap()) as usize;
    let opt = u16::from_le_bytes(pe[coff + 16..coff + 18].try_into().unwrap()) as usize;
    let sec_base = coff + 20 + opt;
    for i in 0..num_sec {
        let sh = sec_base + i * 40;
        if sh + 40 > pe.len() {
            break;
        }
        let chars = u32::from_le_bytes(pe[sh + 36..sh + 40].try_into().unwrap());
        if chars & 0x2000_0020 == 0 {
            continue; // not CODE|EXECUTE
        }
        let raw_size = u32::from_le_bytes(pe[sh + 16..sh + 20].try_into().unwrap()) as usize;
        let raw_ptr = u32::from_le_bytes(pe[sh + 20..sh + 24].try_into().unwrap()) as usize;
        if raw_ptr > 0 && raw_size > 0 && raw_ptr < pe.len() {
            out.push((raw_ptr, raw_size));
        }
    }
    out
}
