use crate::{scanner::scan_workshop_item, state::ScanState};
use dioxus::dioxus_core::spawn_forever;
use dioxus::prelude::*;
use std::path::PathBuf;

#[component]
pub fn ScanPicker(
    mut selected_path: Signal<Option<PathBuf>>,
    mut scan_state: Signal<ScanState>,
    is_dragging: bool,
) -> Element {
    let selected = selected_path.read().clone();
    let is_running = matches!(&*scan_state.read(), ScanState::Running);
    let can_scan = selected.is_some() && !is_running;

    rsx! {
        section { class: "scan-card",
            div { class: if is_dragging { "drop-area active" } else { "drop-area" },
                div { class: "folder-icon",
                    svg {
                        width: "34",
                        height: "34",
                        view_box: "0 0 24 24",
                        fill: "none",
                        stroke: "currentColor",
                        stroke_width: "1.5",
                        path { d: "M3 7h7l2 2h9v10H3z" }
                        path { d: "M12 17v-6" }
                        path { d: "M9.5 13.5L12 11l2.5 2.5" }
                    }
                }
                if is_dragging {
                    h2 { "Drop the map here" }
                    p { "We'll select this folder for scanning." }
                } else if let Some(path) = selected.as_ref() {
                    h2 {
                        "{path.file_name().and_then(|name| name.to_str()).unwrap_or(\"Workshop map\")}"
                    }
                    p { class: "selected-path", "{path.display()}" }
                } else {
                    h2 { "Choose a Workshop map" }
                    p { "Drop its folder here, or find it on your computer." }
                }

                button {
                    class: "button secondary",
                    disabled: is_running,
                    onclick: move |_| {
                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                            selected_path.set(Some(path));
                            scan_state.set(ScanState::Ready);
                        }
                    },
                    if selected.is_some() { "Choose a different folder" } else { "Browse for folder" }
                }
            }

            button {
                class: "button primary",
                disabled: !can_scan,
                onclick: move |_| {
                    let Some(path) = selected_path.read().clone() else {
                        return;
                    };
                    scan_state.set(ScanState::Running);
                    // Running replaces this picker with the result view. A
                    // scope-owned task would be canceled as soon as that
                    // unmount happens, so the scan must outlive this component.
                    spawn_forever(async move {
                        match scan_workshop_item(path).await {
                            Ok(outcome) => scan_state.set(ScanState::Complete(Box::new(outcome))),
                            Err(error) => scan_state.set(ScanState::Error(error.to_string())),
                        }
                    });
                },
                if is_running {
                    span { class: "small-spinner" }
                    "Scanning map…"
                } else {
                    svg {
                        width: "18",
                        height: "18",
                        view_box: "0 0 24 24",
                        fill: "none",
                        stroke: "currentColor",
                        stroke_width: "1.8",
                        path { d: "M12 3l7 3v5c0 4.7-2.8 8.2-7 10-4.2-1.8-7-5.3-7-10V6l7-3z" }
                        path { d: "M9 12l2 2 4-5" }
                    }
                    "Scan this map"
                }
            }
        }
    }
}
