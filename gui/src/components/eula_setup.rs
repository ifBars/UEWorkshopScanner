use crate::state::SetupState;
use dioxus::prelude::*;

#[component]
pub fn EulaSetup(mut setup_state: Signal<SetupState>) -> Element {
    let is_accepting = matches!(&*setup_state.read(), SetupState::Accepting);
    let error = match &*setup_state.read() {
        SetupState::Error(error) => Some(error.clone()),
        _ => None,
    };

    rsx! {
        section { class: "eula-setup",
            p { class: "result-label", "ONE-TIME SETUP" }
            h2 { "Review the bundled binary terms" }
            p { class: "eula-intro",
                "The complete Windows package includes Epic Games' Oodle decoder so the scanner can read compressed Unreal Engine maps. Review and accept these terms before scanning."
            }

            pre { class: "eula-text", "{ue_workshop_scanner::licensing::binary_eula_text()}" }

            if let Some(error) = error {
                div { class: "setup-error",
                    strong { "Setup could not finish" }
                    p { "{error}" }
                }
            }

            button {
                class: "button primary",
                disabled: is_accepting,
                onclick: move |_| {
                    setup_state.set(SetupState::Accepting);
                    spawn(async move {
                        let result = tokio::task::spawn_blocking(
                            ue_workshop_scanner::licensing::accept_bundled_eula
                        ).await;
                        match result {
                            Ok(Ok(())) => setup_state.set(SetupState::Ready),
                            Ok(Err(error)) => setup_state.set(SetupState::Error(error.to_string())),
                            Err(error) => setup_state.set(SetupState::Error(
                                format!("the setup task stopped unexpectedly: {error}")
                            )),
                        }
                    });
                },
                if is_accepting {
                    span { class: "small-spinner" }
                    "Saving acceptance…"
                } else {
                    "I have read and accept these terms"
                }
            }

            p { class: "eula-decline",
                "If you do not agree, close UEWorkshopScanner. The bundled decoder will not be loaded."
            }
        }
    }
}
