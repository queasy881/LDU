//! Native file dialogs (rfd).
//!
//! Both helpers run the native modal picker synchronously and return the chosen
//! absolute path (or `None` on cancel). Callers in `ipc.rs` invoke them on a
//! spawned worker thread so the UI thread is never blocked by the modal loop.

/// Open a native file picker for choosing a binary to analyze. Returns the
/// absolute path as a string, or `None` if the user cancelled.
pub fn open_binary() -> Option<String> {
    rfd::FileDialog::new()
        .set_title("Add binary")
        .add_filter("Binaries", &["exe", "dll", "sys"])
        .add_filter("All files", &["*"])
        .pick_file()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Open a native picker for a `.dsproj` project file. Returns the absolute path
/// or `None` if the user cancelled. Defaults to the projects directory.
pub fn open_project() -> Option<String> {
    let dir = crate::dsproj::projects_dir();
    rfd::FileDialog::new()
        .set_title("Open project")
        .add_filter("DisasmStudio project", &["dsproj"])
        .add_filter("All files", &["*"])
        .set_directory(dir)
        .pick_file()
        .map(|p| p.to_string_lossy().into_owned())
}
