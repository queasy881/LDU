//! `disasm://app/...` custom protocol handler (multi-window edition).
//!
//! Every frontend asset is embedded into the binary at compile time
//! (`include_str!`), so the shipped executable is fully self-contained and needs
//! no working directory or network access.
//!
//! Three HTML pages back the three window roles (launcher / project / disasm),
//! plus the shared CSS/JS each page links. The default route
//! ("", "/", "index.html", "launcher.html") serves the launcher page.

use std::borrow::Cow;
use wry::http::{header::CONTENT_TYPE, Request, Response};

// --- embedded frontend assets (paths relative to THIS file) -----------------
// crates/shell/src/protocol.rs  ->  ../../../frontend/...
const LAUNCHER_HTML: &str = include_str!("../../../frontend/launcher.html");
const PROJECT_HTML: &str = include_str!("../../../frontend/project.html");
const DISASM_HTML: &str = include_str!("../../../frontend/disasm.html");

const MAIN_CSS: &str = include_str!("../../../frontend/css/main.css");
const LAUNCHER_CSS: &str = include_str!("../../../frontend/css/launcher.css");
const PROJECT_CSS: &str = include_str!("../../../frontend/css/project.css");
const DISASM_CSS: &str = include_str!("../../../frontend/css/disasm.css");

const JS_IPC: &str = include_str!("../../../frontend/js/ipc.js");
const JS_UTIL: &str = include_str!("../../../frontend/js/util.js");
const JS_VLIST: &str = include_str!("../../../frontend/js/vlist.js");
const JS_CORE: &str = include_str!("../../../frontend/js/core.js");
const JS_LAUNCHER: &str = include_str!("../../../frontend/js/launcher.js");
const JS_PROJECT: &str = include_str!("../../../frontend/js/project.js");
const JS_DISASM: &str = include_str!("../../../frontend/js/disasm.js");

/// Resolve a normalized asset path to its bytes + content type. The default
/// route maps to the launcher page.
fn lookup(path: &str) -> Option<(&'static [u8], &'static str)> {
    // Default route -> the launcher page.
    let p = match path {
        "" | "/" | "index.html" | "launcher.html" => "launcher.html",
        other => other,
    };
    let asset: Option<(&'static [u8], &'static str)> = match p {
        "launcher.html" => Some((LAUNCHER_HTML.as_bytes(), "text/html")),
        "project.html" => Some((PROJECT_HTML.as_bytes(), "text/html")),
        "disasm.html" => Some((DISASM_HTML.as_bytes(), "text/html")),

        "css/main.css" => Some((MAIN_CSS.as_bytes(), "text/css")),
        "css/launcher.css" => Some((LAUNCHER_CSS.as_bytes(), "text/css")),
        "css/project.css" => Some((PROJECT_CSS.as_bytes(), "text/css")),
        "css/disasm.css" => Some((DISASM_CSS.as_bytes(), "text/css")),

        "js/ipc.js" => Some((JS_IPC.as_bytes(), "text/javascript")),
        "js/util.js" => Some((JS_UTIL.as_bytes(), "text/javascript")),
        "js/vlist.js" => Some((JS_VLIST.as_bytes(), "text/javascript")),
        "js/core.js" => Some((JS_CORE.as_bytes(), "text/javascript")),
        "js/launcher.js" => Some((JS_LAUNCHER.as_bytes(), "text/javascript")),
        "js/project.js" => Some((JS_PROJECT.as_bytes(), "text/javascript")),
        "js/disasm.js" => Some((JS_DISASM.as_bytes(), "text/javascript")),
        _ => None,
    };
    asset
}

/// Extract a clean asset path from a request URI.
///
/// wry rewrites custom-protocol URLs differently per platform. On Windows the
/// navigated URL becomes `http://disasm.app/<path>` (host = scheme, path under
/// the `app` authority), elsewhere `disasm://app/<path>`. We normalize both by
/// taking the URI path, then stripping a leading `app/` authority segment if it
/// leaked into the path, plus any leading slash and query/fragment.
fn normalize(uri: &str) -> String {
    // strip scheme://
    let after_scheme = match uri.find("://") {
        Some(i) => &uri[i + 3..],
        None => uri,
    };
    // drop authority (host[:port]) — everything up to the first '/'
    let path_and_rest = match after_scheme.find('/') {
        Some(i) => &after_scheme[i + 1..],
        None => "",
    };
    // drop query/fragment
    let path: &str = path_and_rest
        .split(['?', '#'])
        .next()
        .unwrap_or(path_and_rest);
    // a stray leading "app/" authority that some platforms fold into the path
    let path = path.strip_prefix("app/").unwrap_or(path);
    // collapse any leading slashes
    let path = path.trim_start_matches('/');
    let decoded = decode_percent(path);
    // Defensive: never allow traversal out of the embedded set.
    if decoded.split('/').any(|seg| seg == "..") {
        return String::new();
    }
    decoded
}

/// Minimal percent-decoding so paths with encoded characters still resolve.
fn decode_percent(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h = hex_val(bytes[i + 1]);
            let l = hex_val(bytes[i + 2]);
            if let (Some(h), Some(l)) = (h, l) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// The wry custom-protocol handler. Never panics; unknown paths -> 404.
pub fn handle(request: &Request<Vec<u8>>) -> Response<Cow<'static, [u8]>> {
    let uri = request.uri().to_string();
    let path = normalize(&uri);

    match lookup(&path) {
        Some((body, ctype)) => Response::builder()
            .status(200)
            .header(CONTENT_TYPE, ctype)
            // permissive for our own embedded origin
            .header("Access-Control-Allow-Origin", "*")
            .body(Cow::Borrowed(body))
            .unwrap_or_else(|_| fallback_500()),
        None => Response::builder()
            .status(404)
            .header(CONTENT_TYPE, "text/plain")
            .body(Cow::Owned(b"404 Not Found".to_vec()))
            .unwrap_or_else(|_| fallback_500()),
    }
}

fn fallback_500() -> Response<Cow<'static, [u8]>> {
    // builder only fails on invalid header values, which we don't use here, but
    // keep an infallible path so the handler signature is always satisfied.
    let mut resp = Response::new(Cow::Owned(b"500".to_vec()));
    *resp.status_mut() = wry::http::StatusCode::INTERNAL_SERVER_ERROR;
    resp
}
