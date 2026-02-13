//! Probex Trace Viewer
//!
//! A web-based visualization tool for probex trace files.
//! This crate is frontend-only (WASM).

mod api;
mod app;

fn main() {
    dioxus::launch(app::App);
}
