#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod app;
mod components;
mod scanner;
mod state;
mod view_model;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "ue_workshop_scanner_gui=info"
                    .parse()
                    .expect("valid filter")
            }),
        )
        .init();

    let window = dioxus::desktop::WindowBuilder::new()
        .with_title("UEWorkshopScanner")
        .with_inner_size(dioxus::desktop::LogicalSize::new(780.0, 640.0))
        .with_min_inner_size(dioxus::desktop::LogicalSize::new(680.0, 520.0))
        .with_resizable(true)
        .with_decorations(true);

    dioxus::LaunchBuilder::desktop()
        .with_cfg(dioxus::desktop::Config::new().with_window(window))
        .launch(app::App);
}
