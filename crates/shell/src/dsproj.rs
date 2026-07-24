//! `.dsproj` project model — a named project that tracks a set of analyzed
//! binaries plus per-binary user annotations (comments and marks).
//!
//! Projects live in `~/.disasmstudio/projects/<name>.dsproj` as JSON. The file
//! is loaded when a project window opens and rewritten on every edit (add /
//! remove a binary, set a comment, toggle a mark) so annotations survive across
//! restarts. Parsing is defensive: a corrupt or partially-written file degrades
//! to sensible defaults rather than panicking.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// On-disk project document. Field defaults make older / hand-edited files load.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DsProj {
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_next_id")]
    pub next_id: u64,
    #[serde(default)]
    pub binaries: Vec<DsBinary>,
}

fn default_next_id() -> u64 {
    1
}

/// One binary tracked by a project, with its per-binary annotations.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DsBinary {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub arch: String,
    /// rva (decimal key) -> comment text.
    #[serde(default)]
    pub comments: BTreeMap<u64, String>,
    /// Marked rvas (kept sorted on save).
    #[serde(default)]
    pub marks: Vec<u64>,
}

/// A loaded project plus the absolute path it was loaded from.
#[derive(Clone, Debug)]
pub struct ProjectState {
    pub path: String,
    pub proj: DsProj,
}

impl ProjectState {
    /// Load a project from `path`. A missing or corrupt file yields an error so
    /// the caller can decide to recreate; an empty file degrades to defaults.
    pub fn load(path: &str) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("read project: {e}"))?;
        let mut proj: DsProj = if text.trim().is_empty() {
            DsProj::default()
        } else {
            serde_json::from_str(&text).map_err(|e| format!("parse project: {e}"))?
        };
        if proj.next_id == 0 {
            proj.next_id = 1;
        }
        if proj.name.trim().is_empty() {
            proj.name = name_from_dsproj_path(path);
        }
        Ok(ProjectState {
            path: path.to_string(),
            proj,
        })
    }

    /// Persist the project to its path (pretty JSON). Marks are sorted/deduped.
    pub fn save(&self) -> Result<(), String> {
        if let Some(parent) = Path::new(&self.path).parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create project dir: {e}"))?;
        }
        let mut proj = self.proj.clone();
        for b in proj.binaries.iter_mut() {
            b.marks.sort_unstable();
            b.marks.dedup();
        }
        let text =
            serde_json::to_string_pretty(&proj).map_err(|e| format!("serialize project: {e}"))?;
        fs::write(&self.path, text).map_err(|e| format!("write project: {e}"))
    }

    /// Add a binary by path. Derives the display name from the filename, assigns
    /// the next id, appends it, and returns the new id. Format/arch are probed
    /// cheaply if possible; left blank on failure.
    pub fn add_binary(&mut self, bin_path: &str) -> u64 {
        let id = self.proj.next_id.max(1);
        self.proj.next_id = id.saturating_add(1);
        let name = file_name_of(bin_path);
        let (format, arch) = probe_format_arch(bin_path);
        self.proj.binaries.push(DsBinary {
            id,
            path: bin_path.to_string(),
            name,
            format,
            arch,
            comments: BTreeMap::new(),
            marks: Vec::new(),
        });
        id
    }

    /// Remove the binary with `id` (no-op if absent).
    pub fn remove_binary(&mut self, id: u64) {
        self.proj.binaries.retain(|b| b.id != id);
    }

    pub fn binary(&self, id: u64) -> Option<&DsBinary> {
        self.proj.binaries.iter().find(|b| b.id == id)
    }

    fn binary_mut(&mut self, id: u64) -> Option<&mut DsBinary> {
        self.proj.binaries.iter_mut().find(|b| b.id == id)
    }

    /// Set (or, for empty/whitespace text, delete) a comment on `rva`.
    pub fn set_comment(&mut self, id: u64, rva: u64, text: &str) {
        if let Some(b) = self.binary_mut(id) {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                b.comments.remove(&rva);
            } else {
                b.comments.insert(rva, trimmed.to_string());
            }
        }
    }

    /// Toggle a mark on `rva`; returns the new marked state.
    pub fn toggle_mark(&mut self, id: u64, rva: u64) -> bool {
        if let Some(b) = self.binary_mut(id) {
            if let Some(pos) = b.marks.iter().position(|&m| m == rva) {
                b.marks.remove(pos);
                false
            } else {
                b.marks.push(rva);
                b.marks.sort_unstable();
                true
            }
        } else {
            false
        }
    }

    /// Comments as a JSON object keyed by decimal-rva strings (IPC shape).
    pub fn comments_json(&self, id: u64) -> Value {
        match self.binary(id) {
            Some(b) => {
                let map: serde_json::Map<String, Value> = b
                    .comments
                    .iter()
                    .map(|(rva, text)| (rva.to_string(), Value::String(text.clone())))
                    .collect();
                Value::Object(map)
            }
            None => json!({}),
        }
    }

    /// Sorted marks for a binary.
    pub fn marks_vec(&self, id: u64) -> Vec<u64> {
        match self.binary(id) {
            Some(b) => {
                let mut v = b.marks.clone();
                v.sort_unstable();
                v.dedup();
                v
            }
            None => Vec::new(),
        }
    }

    /// The binaries as the launcher/project IPC list shape.
    pub fn binaries_json(&self) -> Value {
        Value::Array(
            self.proj
                .binaries
                .iter()
                .map(|b| {
                    json!({
                        "id": b.id,
                        "name": b.name,
                        "path": b.path,
                        "format": b.format,
                        "arch": b.arch,
                    })
                })
                .collect(),
        )
    }
}

/// `~/.disasmstudio/projects`, created if absent.
pub fn projects_dir() -> PathBuf {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = home.join(".disasmstudio").join("projects");
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Reduce an arbitrary name to a safe single-path-component filename stem.
/// Keeps ASCII alphanumerics, space, dash, underscore, and dot; collapses the
/// rest to '_'. Trims, caps length, and never returns empty.
pub fn sanitize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, ' ' | '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim().trim_matches('.').trim();
    let mut s: String = trimmed.chars().take(120).collect();
    if s.is_empty() {
        s = "project".to_string();
    }
    s
}

/// Create a new project file `<sanitized>.dsproj`. If a file with that stem
/// already exists, append a counter (`-2`, `-3`, …) until a free name is found.
/// Returns the freshly written, in-memory `ProjectState`.
pub fn create(name: &str) -> Result<ProjectState, String> {
    let dir = projects_dir();
    let base = sanitize_name(name);
    let mut stem = base.clone();
    let mut counter = 2u32;
    let mut path = dir.join(format!("{stem}.dsproj"));
    while path.exists() {
        stem = format!("{base}-{counter}");
        path = dir.join(format!("{stem}.dsproj"));
        counter = counter.saturating_add(1);
        if counter > 10_000 {
            return Err("could not find a free project name".to_string());
        }
    }
    let proj = DsProj {
        name: stem.clone(),
        next_id: 1,
        binaries: Vec::new(),
    };
    let state = ProjectState {
        path: path.to_string_lossy().into_owned(),
        proj,
    };
    state.save()?;
    Ok(state)
}

/// Path of the shared scratch project used for CLI-launched binaries.
pub fn scratch_path() -> PathBuf {
    projects_dir().join("_scratch.dsproj")
}

/// Load the scratch project, creating it if absent.
pub fn load_or_create_scratch() -> Result<ProjectState, String> {
    let path = scratch_path();
    let path_str = path.to_string_lossy().into_owned();
    if path.exists() {
        ProjectState::load(&path_str)
    } else {
        let proj = DsProj {
            name: "_scratch".to_string(),
            next_id: 1,
            binaries: Vec::new(),
        };
        let state = ProjectState {
            path: path_str,
            proj,
        };
        state.save()?;
        Ok(state)
    }
}

/// One entry in the launcher's recent-projects list.
#[derive(Serialize, Clone, Debug)]
pub struct RecentProject {
    pub name: String,
    pub path: String,
    pub binary_count: usize,
}

/// Scan the projects directory for `*.dsproj`, tolerating corrupt files. Hidden
/// scratch projects (leading underscore) are skipped.
pub fn list_recent() -> Vec<RecentProject> {
    let dir = projects_dir();
    let mut out: Vec<RecentProject> = Vec::new();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_dsproj = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("dsproj"))
            .unwrap_or(false);
        if !is_dsproj {
            continue;
        }
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if stem.starts_with('_') {
            continue;
        }
        let path_str = path.to_string_lossy().into_owned();
        let (name, count) = match fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<DsProj>(&text) {
                Ok(p) => {
                    let n = if p.name.trim().is_empty() {
                        stem.to_string()
                    } else {
                        p.name
                    };
                    (n, p.binaries.len())
                }
                Err(_) => (stem.to_string(), 0),
            },
            Err(_) => (stem.to_string(), 0),
        };
        out.push(RecentProject {
            name,
            path: path_str,
            binary_count: count,
        });
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

fn file_name_of(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
        .to_string()
}

fn name_from_dsproj_path(path: &str) -> String {
    Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("project")
        .to_string()
}

/// Best-effort format/arch probe used when adding a binary. Failures are not
/// fatal — the fields just stay blank and analysis fills the real values later.
fn probe_format_arch(path: &str) -> (String, String) {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(_) => return (String::new(), String::new()),
    };
    match binparser::BinaryMeta::parse(&bytes) {
        Ok(meta) => (
            format_label(meta.format).to_string(),
            arch_label(meta.arch).to_string(),
        ),
        Err(_) => (String::new(), String::new()),
    }
}

pub fn format_label(f: binparser::Format) -> &'static str {
    use binparser::Format as F;
    match f {
        F::Pe32 => "PE32",
        F::Pe32Plus => "PE32+",
        F::Elf32 => "ELF32",
        F::Elf64 => "ELF64",
        F::MachO32 => "Mach-O 32",
        F::MachO64 => "Mach-O 64",
    }
}

pub fn arch_label(a: binparser::Arch) -> &'static str {
    use binparser::Arch as A;
    match a {
        A::X86 => "x86",
        A::X64 => "x64",
        A::Arm => "ARM",
        A::Arm64 => "ARM64",
        A::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> String {
        std::env::temp_dir()
            .join(format!("ds_test_{}_{}.dsproj", std::process::id(), tag))
            .to_string_lossy()
            .into_owned()
    }

    /// Comments and marks set on a project must survive a save -> reload, keyed
    /// per-binary by rva. This is the "saves in a .dsproj loaded every time"
    /// guarantee.
    #[test]
    fn comments_and_marks_persist_across_reload() {
        let path = tmp_path("persist");
        let _ = fs::remove_file(&path);

        let mut st = ProjectState {
            path: path.clone(),
            proj: DsProj {
                name: "t".into(),
                next_id: 1,
                binaries: Vec::new(),
            },
        };
        let id = st.add_binary(r"C:\does\not\matter\thing.bin");
        st.set_comment(id, 0x1000, "loop start");
        st.set_comment(id, 0x1abc, "  decrypt routine  "); // trimmed on store
        assert!(st.toggle_mark(id, 0x1000)); // -> marked
        assert!(st.toggle_mark(id, 0x2000)); // -> marked
        assert!(!st.toggle_mark(id, 0x1000)); // toggled off
        st.save().expect("save");

        // Reload a fresh instance from disk and verify persistence.
        let re = ProjectState::load(&path).expect("reload");
        let b = re.binary(id).expect("binary present after reload");
        assert_eq!(b.comments.get(&0x1000).map(String::as_str), Some("loop start"));
        assert_eq!(b.comments.get(&0x1abc).map(String::as_str), Some("decrypt routine"));
        assert_eq!(re.marks_vec(id), vec![0x2000]); // 0x1000 was toggled off
        // comments_json IPC shape uses decimal-string keys.
        let cj = re.comments_json(id);
        assert_eq!(cj[&0x1000u64.to_string()], serde_json::json!("loop start"));

        // Empty text deletes a comment, and that deletion persists too.
        let mut re2 = re;
        re2.set_comment(id, 0x1000, "   ");
        re2.save().expect("save2");
        let re3 = ProjectState::load(&path).expect("reload2");
        assert!(re3.binary(id).unwrap().comments.get(&0x1000).is_none());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn add_remove_binary_and_sanitize() {
        let path = tmp_path("binlist");
        let _ = fs::remove_file(&path);
        let mut st = ProjectState {
            path: path.clone(),
            proj: DsProj::default(),
        };
        let a = st.add_binary(r"C:\a\one.exe");
        let b = st.add_binary(r"C:\b\two.dll");
        assert_ne!(a, b);
        assert_eq!(st.proj.binaries.len(), 2);
        assert_eq!(st.binary(b).unwrap().name, "two.dll");
        st.remove_binary(a);
        assert_eq!(st.proj.binaries.len(), 1);
        assert!(st.binary(a).is_none());

        assert_eq!(sanitize_name("My Project!"), "My Project_");
        assert_eq!(sanitize_name(r"a/b\c:d"), "a_b_c_d"); // path separators -> '_'
        assert!(!sanitize_name("").is_empty());
        assert!(!sanitize_name("/\\:*?").contains('/'));
        let _ = fs::remove_file(&path);
    }
}
