use crate::{
    components::{EulaSetup, ResultView, ScanPicker},
    state::{ScanState, SetupState},
};
use dioxus::prelude::*;
use dioxus_desktop::{
    tao::{
        dpi::LogicalSize,
        event::{Event, WindowEvent},
    },
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
    let desktop = dioxus_desktop::window();

    use_effect(move || {
        let target_height = target_window_height(&scan_state.read(), &setup_state.read());

        if desktop.is_maximized() || desktop.fullscreen().is_some() {
            return;
        }

        let physical_size = desktop.inner_size();
        let logical_size = physical_size.to_logical::<f64>(desktop.scale_factor());
        desktop.set_inner_size(LogicalSize::new(logical_size.width, target_height));
    });

    let _drop_handler = use_wry_event_handler(move |event, _| match event {
        Event::WindowEvent {
            event: WindowEvent::HoveredFile(_),
            ..
        } => is_dragging.set(true),
        Event::WindowEvent {
            event: WindowEvent::HoveredFileCancelled,
            ..
        } => is_dragging.set(false),
        Event::WindowEvent {
            event: WindowEvent::DroppedFile(path),
            ..
        } => {
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

                ScanPicker {
                    selected_path,
                    scan_state,
                    is_dragging: is_dragging()
                }
                ResultView { scan_state }
            } else {
                EulaSetup { setup_state }
            }

            footer {
                "A clean result lowers risk, but no scanner can guarantee a map is safe. Keep your antivirus enabled."
            }
        }
    }
}

fn target_window_height(scan_state: &ScanState, setup_state: &SetupState) -> f64 {
    if !setup_state.is_ready() {
        return 720.0;
    }

    match scan_state {
        ScanState::Ready => 490.0,
        ScanState::Running => 560.0,
        ScanState::Complete(_) | ScanState::Error(_) => 720.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_for_results_and_errors() {
        assert_eq!(
            target_window_height(&ScanState::Ready, &SetupState::Ready),
            490.0
        );
        assert_eq!(
            target_window_height(&ScanState::Running, &SetupState::Ready),
            560.0
        );
        assert_eq!(
            target_window_height(&ScanState::Error("test".to_owned()), &SetupState::Ready),
            720.0
        );
        assert_eq!(
            target_window_height(&ScanState::Ready, &SetupState::EulaRequired),
            720.0
        );
    }
}
