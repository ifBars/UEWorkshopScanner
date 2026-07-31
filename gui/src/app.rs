use crate::{
    components::{EulaSetup, ResultView, ScanPicker},
    state::{ScanState, SetupState},
};
use dioxus::prelude::*;
use dioxus_desktop::{
    tao::event::{Event, WindowEvent},
    use_wry_event_handler,
};
use std::path::PathBuf;

const APP_CSS: &str = include_str!("../assets/main.css");

#[component]
pub fn App() -> Element {
    let mut selected_path = use_signal(|| None::<PathBuf>);
    let mut scan_state = use_signal(ScanState::default);
    let setup_state = use_signal(SetupState::initial);
    let mut is_dragging = use_signal(|| false);

    let _drop_handler = use_wry_event_handler(move |event, _| match event {
        Event::WindowEvent {
            event: WindowEvent::HoveredFile(_),
            ..
        } if scan_state.read().shows_picker() => is_dragging.set(true),
        Event::WindowEvent {
            event: WindowEvent::HoveredFileCancelled,
            ..
        } => is_dragging.set(false),
        Event::WindowEvent {
            event: WindowEvent::DroppedFile(path),
            ..
        } if scan_state.read().shows_picker() => {
            is_dragging.set(false);
            selected_path.set(Some(path.to_path_buf()));
            scan_state.set(ScanState::Ready);
        }
        _ => {}
    });

    rsx! {
        style { dangerous_inner_html: APP_CSS }
        main { class: "app",
            header { class: "app-header",
                div { class: "brand",
                    div { class: "brand-icon",
                        svg {
                            width: "24",
                            height: "24",
                            view_box: "0 0 24 24",
                            fill: "none",
                            stroke: "currentColor",
                            stroke_width: "1.7",
                            path { d: "M12 3l7 3v5c0 4.7-2.8 8.2-7 10-4.2-1.8-7-5.3-7-10V6l7-3z" }
                            path { d: "M9 12l2 2 4-5" }
                        }
                    }
                    div {
                        h1 { "UEWorkshopScanner" }
                        p { "Check a Workshop map before you play it." }
                    }
                }
                span { class: "experimental", "EXPERIMENTAL" }
            }

            if setup_state.read().is_ready() {
                div { class: "supported-game",
                    span { class: "game-dot" }
                    "Currently supports MECCHA CHAMELEON maps"
                }

                if scan_state.read().shows_picker() {
                    ScanPicker {
                        selected_path,
                        scan_state,
                        is_dragging: is_dragging()
                    }
                }
                ResultView { scan_state, selected_path }
            } else {
                EulaSetup { setup_state }
            }

            footer {
                "A clean result lowers risk, but no scanner can guarantee a map is safe. Keep your antivirus enabled."
            }
        }
    }
}
