//! DisasmStudio — native shell entry point (multi-window host).
//!
//! Three OS window roles, each its own HTML page served over the `disasm://`
//! custom protocol:
//!   LAUNCHER  -> launcher.html  (main window; created at startup; closing exits)
//!   PROJECT   -> project.html   (one per open .dsproj)
//!   DISASM    -> disasm.html    (one per opened binary; analysis auto-starts)
//!
//! wry's IPC handler fires on the UI thread but cannot capture the `WebView`
//! (it does not exist when the builder is configured). Each window's handler
//! captures the event-loop proxy, that window's `WindowId`, and a role-specific
//! `ipc::RoleCtx`, and forwards `ipc::dispatch(&ctx, win, &body)`. Replies and
//! pushes route back to the right window through `UserEvent::Ipc { target, js }`,
//! which the loop turns into `webview.evaluate_script` on the owning window.
//!
//! `bridge::Engine` is `unsafe impl Send`, so analysis builds the engine on a
//! worker thread and commits the finished `Session` under its `Mutex` (mirroring
//! the original `app.rs`); there is no separate UI-thread finalize event.
//!
//! All frontend assets are embedded (`include_str!`, see `protocol.rs`); nothing
//! is read from disk at runtime.

#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

mod dialogs;
mod dsproj;
mod ipc;
mod protocol;
mod script;
mod session;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tao::dpi::LogicalSize;
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy, EventLoopWindowTarget};
use tao::window::{Theme, Window, WindowBuilder, WindowId};
use wry::{WebView, WebViewBuilder};

use dsproj::ProjectState;
use ipc::{Role, RoleCtx};
use session::{Session, SharedSession};

/// Custom events delivered to the main event loop.
pub enum UserEvent {
    /// Evaluate `js` in the window identified by `target` (replies / pushes).
    Ipc { target: WindowId, js: String },
    /// Create a new project named `name` and open a PROJECT window for it.
    NewProject { name: String },
    /// Load (or reuse) the .dsproj at `path` and open a PROJECT window.
    OpenProjectFile { path: String },
    /// Open a DISASM window for binary `bin_id` in project `proj_path`.
    OpenBinary { proj_path: String, bin_id: u64 },
    /// CLI-launched binary path: open it in a scratch project's disasm window.
    AutoOpen { path: String },
    /// Close the given window (and exit if it was the launcher).
    CloseWindow(WindowId),
}

/// A live window: its tao `Window`, its wry `WebView`, and its role. Both the
/// window and the webview must stay alive for the page to keep running.
#[allow(dead_code)]
struct WinEntry {
    /// Both must stay alive for the page to keep running.
    window: Window,
    webview: WebView,
    /// Retained for diagnostics; behavior is bound at build time.
    role: Role,
}

/// Owns every live window plus the set of open projects (shared with the disasm
/// windows that annotate them) and the per-disasm sessions.
struct Manager {
    proxy: EventLoopProxy<UserEvent>,
    windows: HashMap<WindowId, WinEntry>,
    /// .dsproj path -> shared project state. One entry per distinct open project.
    projects: HashMap<String, Arc<Mutex<ProjectState>>>,
    /// Sessions keyed by their disasm window id (kept so close can cancel them).
    sessions: HashMap<WindowId, SharedSession>,
    launcher_id: Option<WindowId>,
}

impl Manager {
    fn new(proxy: EventLoopProxy<UserEvent>) -> Manager {
        Manager {
            proxy,
            windows: HashMap::new(),
            projects: HashMap::new(),
            sessions: HashMap::new(),
            launcher_id: None,
        }
    }

    /// Get the shared state for `proj_path`, loading (or, on failure, defaulting)
    /// it into the map if not already open.
    fn project_arc(&mut self, proj_path: &str) -> Arc<Mutex<ProjectState>> {
        if let Some(arc) = self.projects.get(proj_path) {
            return arc.clone();
        }
        let state = ProjectState::load(proj_path).unwrap_or_else(|_| ProjectState {
            path: proj_path.to_string(),
            proj: dsproj::DsProj::default(),
        });
        let arc = Arc::new(Mutex::new(state));
        self.projects.insert(proj_path.to_string(), arc.clone());
        arc
    }
}

/// Create just the native window for a role (no webview yet). Splitting the two
/// lets the caller learn the `WindowId` before building the IPC context — the
/// disasm role needs its window id inside the `Session` the context captures.
fn build_native_window<T>(
    target: &EventLoopWindowTarget<T>,
    title: &str,
    size: (f64, f64),
) -> Result<Window, String> {
    WindowBuilder::new()
        .with_title(title)
        .with_inner_size(LogicalSize::new(size.0, size.1))
        .with_min_inner_size(LogicalSize::new(
            (size.0 * 0.6).max(400.0),
            (size.1 * 0.6).max(320.0),
        ))
        .with_theme(Some(Theme::Dark))
        .build(target)
        .map_err(|e| format!("create window: {e}"))
}

/// Attach a webview (shared protocol + an IPC handler bound to `ctx`) to an
/// already-built `window`, returning the finished `WinEntry`.
fn attach_webview(
    window: Window,
    win_id: WindowId,
    page: &str,
    ctx: RoleCtx,
    role: Role,
) -> Result<WinEntry, String> {
    let url = format!("disasm://app/{page}");

    let protocol_handler =
        move |_id: wry::WebViewId, request: wry::http::Request<Vec<u8>>| protocol::handle(&request);

    let ipc_handler = move |req: wry::http::Request<String>| {
        // Never block the UI thread; dispatch synchronously. Replies route back
        // through the proxy; dialogs spawn their own threads.
        ipc::dispatch(&ctx, win_id, &req.into_body());
    };

    let webview = WebViewBuilder::new()
        .with_custom_protocol("disasm".to_string(), protocol_handler)
        .with_ipc_handler(ipc_handler)
        .with_background_color((0, 0, 0, 255))
        .with_url(&url)
        .build(&window)
        .map_err(|e| format!("create webview: {e}"))?;

    Ok(WinEntry {
        window,
        webview,
        role,
    })
}

/// Convenience for roles whose context needs no window id up front.
fn build_window<T>(
    target: &EventLoopWindowTarget<T>,
    title: &str,
    size: (f64, f64),
    page: &str,
    ctx: RoleCtx,
    role: Role,
) -> Result<(WindowId, WinEntry), String> {
    let window = build_native_window(target, title, size)?;
    let win_id = window.id();
    let entry = attach_webview(window, win_id, page, ctx, role)?;
    Ok((win_id, entry))
}

fn main() {
    /* Headless scripting mode: run the JSON command stream and exit WITHOUT ever
     * building an event loop or a window, so it works over a pipe, in CI, and on a
     * machine with no display. Checked before anything GUI is constructed. */
    {
        let argv: Vec<String> = std::env::args().skip(1).collect();
        if argv.first().map(String::as_str) == Some("--script") {
            std::process::exit(script::run(&argv[1..]));
        }
    }
    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    let mut manager = Manager::new(proxy.clone());

    // Create the LAUNCHER window before run().
    let launcher_ctx = RoleCtx::Launcher {
        proxy: proxy.clone(),
    };
    match build_window(
        &event_loop,
        "DisasmStudio",
        (900.0, 600.0),
        "launcher.html",
        launcher_ctx,
        Role::Launcher,
    ) {
        Ok((id, entry)) => {
            manager.launcher_id = Some(id);
            manager.windows.insert(id, entry);
        }
        Err(e) => {
            eprintln!("fatal: {e}");
            std::process::exit(1);
        }
    }

    // Optional CLI binary path -> auto-open after the loop starts.
    let cli_path = std::env::args().nth(1);

    event_loop.run(move |event, target, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => {
                if let Some(path) = cli_path.clone() {
                    if !path.trim().is_empty() {
                        let _ = manager.proxy.send_event(UserEvent::AutoOpen { path });
                    }
                }
            }

            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                window_id,
                ..
            } => {
                handle_close(&mut manager, window_id, control_flow);
            }

            Event::UserEvent(ue) => match ue {
                UserEvent::Ipc { target: t, js } => {
                    if let Some(entry) = manager.windows.get(&t) {
                        let _ = entry.webview.evaluate_script(&js);
                    }
                }
                UserEvent::NewProject { name } => match dsproj::create(&name) {
                    Ok(state) => open_project_window(&mut manager, &proxy, target, state),
                    Err(e) => eprintln!("new_project failed: {e}"),
                },
                UserEvent::OpenProjectFile { path } => {
                    let arc = manager.project_arc(&path);
                    let state = lock_state(&arc);
                    open_project_window(&mut manager, &proxy, target, state);
                }
                UserEvent::OpenBinary { proj_path, bin_id } => {
                    open_binary_window(&mut manager, &proxy, target, &proj_path, bin_id);
                }
                UserEvent::AutoOpen { path } => {
                    auto_open(&mut manager, &proxy, target, &path);
                }
                UserEvent::CloseWindow(id) => {
                    handle_close(&mut manager, id, control_flow);
                }
            },

            _ => {}
        }
    });
}

/// Snapshot a project state, recovering from a poisoned lock.
fn lock_state(arc: &Arc<Mutex<ProjectState>>) -> ProjectState {
    match arc.lock() {
        Ok(g) => g.clone(),
        Err(p) => p.into_inner().clone(),
    }
}

/// Close a window. Closing the launcher exits the app; closing any other window
/// just drops it (and cancels / drops its session, if a disasm window).
fn handle_close(manager: &mut Manager, window_id: WindowId, control_flow: &mut ControlFlow) {
    let was_launcher = manager.launcher_id == Some(window_id);
    if let Some(entry) = manager.windows.remove(&window_id) {
        // Cancel a running analysis for a disasm window.
        if let Some(sess) = manager.sessions.remove(&window_id) {
            let guard = match sess.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard
                .cancel
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        drop(entry); // drops WebView then Window.
    }
    if was_launcher {
        *control_flow = ControlFlow::Exit;
    }
}

/// Insert a project arc (keyed by path) and open a PROJECT window for it.
fn open_project_window<T>(
    manager: &mut Manager,
    proxy: &EventLoopProxy<UserEvent>,
    target: &EventLoopWindowTarget<T>,
    state: ProjectState,
) {
    let proj_path = state.path.clone();
    let proj_name = state.proj.name.clone();
    // Register / refresh the shared state.
    let arc = manager
        .projects
        .entry(proj_path.clone())
        .or_insert_with(|| Arc::new(Mutex::new(state.clone())))
        .clone();

    let ctx = RoleCtx::Project {
        proxy: proxy.clone(),
        proj: arc,
        proj_path: proj_path.clone(),
    };
    let title = format!("DisasmStudio — {proj_name}");
    match build_window(
        target,
        &title,
        (720.0, 520.0),
        "project.html",
        ctx,
        Role::Project { proj_path },
    ) {
        Ok((id, entry)) => {
            manager.windows.insert(id, entry);
        }
        Err(e) => eprintln!("open project window failed: {e}"),
    }
}

/// Open a DISASM window for `bin_id` in the project at `proj_path` and start
/// analysis on a worker thread pushing to that window.
fn open_binary_window<T>(
    manager: &mut Manager,
    proxy: &EventLoopProxy<UserEvent>,
    target: &EventLoopWindowTarget<T>,
    proj_path: &str,
    bin_id: u64,
) {
    let arc = manager.project_arc(proj_path);
    let (bin_path, bin_name, proj_name) = {
        let p = match arc.lock() {
            Ok(g) => g,
            Err(po) => po.into_inner(),
        };
        match p.binary(bin_id) {
            Some(b) => (b.path.clone(), b.name.clone(), p.proj.name.clone()),
            None => {
                eprintln!("open_binary: binary {bin_id} not found in {proj_path}");
                return;
            }
        }
    };

    // Build the native window first so we know its real WindowId, then create
    // the session bound to that id, then attach the webview whose IPC context
    // captures the session.
    let title = format!("DisasmStudio — {bin_name}");
    let window = match build_native_window(target, &title, (1400.0, 900.0)) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("open disasm window failed: {e}");
            return;
        }
    };
    let win_id = window.id();

    let session: SharedSession = Arc::new(Mutex::new(Session::new(
        proxy.clone(),
        win_id,
        bin_path,
        bin_name,
        proj_name,
    )));

    let ctx = RoleCtx::Disasm {
        proxy: proxy.clone(),
        session: session.clone(),
        proj: arc.clone(),
        bin_id,
    };

    match attach_webview(window, win_id, "disasm.html", ctx, Role::Disasm) {
        Ok(entry) => {
            manager.windows.insert(win_id, entry);
            manager.sessions.insert(win_id, session.clone());
            session::start_analysis(&session);
        }
        Err(e) => eprintln!("attach disasm webview failed: {e}"),
    }
}

/// CLI auto-open: add `path` to the shared scratch project (if missing) and open
/// a disasm window for it.
fn auto_open<T>(
    manager: &mut Manager,
    proxy: &EventLoopProxy<UserEvent>,
    target: &EventLoopWindowTarget<T>,
    path: &str,
) {
    let scratch = match dsproj::load_or_create_scratch() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("scratch project: {e}");
            return;
        }
    };
    let scratch_path = scratch.path.clone();
    let arc = manager
        .projects
        .entry(scratch_path.clone())
        .or_insert_with(|| Arc::new(Mutex::new(scratch)))
        .clone();

    let bin_id = {
        let mut p = match arc.lock() {
            Ok(g) => g,
            Err(po) => po.into_inner(),
        };
        // Reuse an existing entry for this path if present, else add it.
        let existing = p
            .proj
            .binaries
            .iter()
            .find(|b| b.path == path)
            .map(|b| b.id);
        match existing {
            Some(id) => id,
            None => {
                let id = p.add_binary(path);
                let _ = p.save();
                id
            }
        }
    };
    open_binary_window(manager, proxy, target, &scratch_path, bin_id);
}
