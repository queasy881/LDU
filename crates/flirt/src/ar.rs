//! `ar` archive reader — the `!<arch>\n` container used by BOTH MSVC `.lib` and
//! GNU `.a`. Yields the object members (COFF or ELF); skips the linker symbol
//! index members (`/`, first/second) and resolves long names via the `//` table.

pub struct Member<'a> {
    pub name: String,
    pub data: &'a [u8],
}

/// Parse an ar archive, returning its object members (name + raw bytes). The
/// special `/`, second-linker, and `//` members are consumed for metadata only.
pub fn members(buf: &[u8]) -> Vec<Member<'_>> {
    let mut out = Vec::new();
    if buf.len() < 8 || &buf[0..8] != b"!<arch>\n" {
        return out;
    }
    let mut p = 8usize;
    let mut longnames: &[u8] = &[];
    while p + 60 <= buf.len() {
        let hdr = &buf[p..p + 60];
        // header layout: name[16] date[12] uid[6] gid[6] mode[8] size[10] end[2]
        let raw_name = &hdr[0..16];
        let size = ascii_num(&hdr[48..58]).unwrap_or(0);
        let data_start = p + 60;
        let data_end = data_start.saturating_add(size);
        if data_end > buf.len() {
            break;
        }
        let data = &buf[data_start..data_end];

        let name_field = trim_ascii(raw_name);
        // classify special members
        if name_field == b"/" {
            // GNU symbol table OR MSVC first/second linker member — metadata, skip.
        } else if name_field == b"//" {
            longnames = data; // GNU/MSVC long-name string table
        } else if name_field.first() == Some(&b'/') && name_field.len() > 1
            && name_field[1..].iter().all(|c| c.is_ascii_digit())
        {
            // "/NNN" -> offset into the longnames table (GNU/MSVC)
            let off: usize = std::str::from_utf8(&name_field[1..]).ok().and_then(|s| s.parse().ok()).unwrap_or(0);
            if let Some(nm) = longname_at(longnames, off) {
                out.push(Member { name: nm, data });
            }
        } else {
            // direct name (MSVC pads with spaces; GNU ends short names with '/')
            let mut n = name_field;
            if n.last() == Some(&b'/') {
                n = &n[..n.len() - 1];
            }
            let nm = String::from_utf8_lossy(n).into_owned();
            if !nm.is_empty() {
                out.push(Member { name: nm, data });
            }
        }

        // members are 2-byte aligned (pad with '\n')
        p = data_end + (data_end & 1);
    }
    out
}

fn longname_at(table: &[u8], off: usize) -> Option<String> {
    if off >= table.len() {
        return None;
    }
    let s = &table[off..];
    // terminated by '\n' (GNU) or null (MSVC); strip a trailing '/'
    let end = s.iter().position(|&c| c == b'\n' || c == 0).unwrap_or(s.len());
    let mut n = &s[..end];
    if n.last() == Some(&b'/') {
        n = &n[..n.len() - 1];
    }
    Some(String::from_utf8_lossy(n).into_owned())
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let mut e = b.len();
    while e > 0 && (b[e - 1] == b' ' || b[e - 1] == 0) {
        e -= 1;
    }
    &b[..e]
}

fn ascii_num(b: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(trim_ascii(b)).ok()?;
    s.trim().parse().ok()
}
