use anyhow::{Context, Result, bail};
use std::{ffi::OsString, path::PathBuf};

pub(crate) fn run(args: &[OsString]) -> Result<i32> {
    let options = parse_options(args)?;
    show_warning("UEWorkshopScanner blocked a map", &message(&options))?;
    Ok(0)
}

#[derive(Debug, PartialEq, Eq)]
struct Options {
    item_id: String,
    decision: String,
    report: PathBuf,
}

fn parse_options(args: &[OsString]) -> Result<Options> {
    let mut arguments = args.iter();
    let mut item_id = None;
    let mut decision = None;
    let mut report = None;

    while let Some(argument) = arguments.next() {
        match argument.to_string_lossy().as_ref() {
            "--item-id" => {
                item_id = Some(
                    arguments
                        .next()
                        .context("--item-id needs a value")?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            "--decision" => {
                decision = Some(
                    arguments
                        .next()
                        .context("--decision needs a value")?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            "--report" => {
                report = Some(PathBuf::from(
                    arguments.next().context("--report needs a value")?,
                ));
            }
            unknown => bail!("unknown notification argument: {unknown}"),
        }
    }

    let item_id = item_id.context("--notify-block requires --item-id")?;
    if item_id.is_empty() || !item_id.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("--item-id must contain only digits");
    }

    let decision = decision.context("--notify-block requires --decision")?;
    if !matches!(
        decision.as_str(),
        "review" | "block" | "incomplete" | "error"
    ) {
        bail!("--decision must be review, block, incomplete, or error");
    }

    Ok(Options {
        item_id,
        decision,
        report: report.context("--notify-block requires --report")?,
    })
}

fn message(options: &Options) -> String {
    let reason = match options.decision.as_str() {
        "block" => "The scanner detected suspicious content and blocked the map.",
        "review" => "The scan found content that needs manual review.",
        "incomplete" => "The scanner could not safely complete its analysis.",
        _ => "The scanner encountered an error and could not safely allow the map.",
    };

    format!(
        "UEWorkshopScanner prevented Steam Workshop item {} from loading.\n\n{}\n\n\
         MECCHA CHAMELEON was closed before the map could load.\n\nScan report:\n{}",
        options.item_id,
        reason,
        options.report.display()
    )
}

#[cfg(windows)]
fn message_box(caption: &str, message: &str, message_type: u32) -> Result<i32> {
    use std::{ffi::c_void, iter::once};

    #[link(name = "user32")]
    unsafe extern "system" {
        fn MessageBoxW(
            window: *mut c_void,
            text: *const u16,
            caption: *const u16,
            message_type: u32,
        ) -> i32;
    }

    const MB_SETFOREGROUND: u32 = 0x0001_0000;
    const MB_TOPMOST: u32 = 0x0004_0000;

    let text: Vec<u16> = message.encode_utf16().chain(once(0)).collect();
    let caption: Vec<u16> = caption.encode_utf16().chain(once(0)).collect();

    // SAFETY: Both strings are valid, null-terminated UTF-16 buffers that remain
    // alive for the duration of this synchronous Win32 call.
    let result = unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            message_type | MB_SETFOREGROUND | MB_TOPMOST,
        )
    };
    if result == 0 {
        bail!("Windows could not display the setup message");
    }
    Ok(result)
}

#[cfg(not(windows))]
fn message_box(caption: &str, message: &str, _message_type: u32) -> Result<i32> {
    eprintln!("{caption}\n\n{message}");
    Ok(1)
}

pub(crate) fn show_warning(caption: &str, message: &str) -> Result<()> {
    const MB_OK: u32 = 0x0000_0000;
    const MB_ICONWARNING: u32 = 0x0000_0030;
    message_box(caption, message, MB_OK | MB_ICONWARNING)?;
    Ok(())
}

pub(crate) fn show_information(caption: &str, message: &str) -> Result<()> {
    const MB_OK: u32 = 0x0000_0000;
    const MB_ICONINFORMATION: u32 = 0x0000_0040;
    message_box(caption, message, MB_OK | MB_ICONINFORMATION)?;
    Ok(())
}

pub(crate) fn confirm(caption: &str, message: &str) -> Result<bool> {
    const MB_YESNO: u32 = 0x0000_0004;
    const MB_ICONQUESTION: u32 = 0x0000_0020;
    const IDYES: i32 = 6;
    Ok(message_box(caption, message, MB_YESNO | MB_ICONQUESTION)? == IDYES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_clear_block_message() {
        let options = Options {
            item_id: "123456".to_owned(),
            decision: "block".to_owned(),
            report: PathBuf::from(r"C:\reports\mount-123456.json"),
        };

        let rendered = message(&options);

        assert!(rendered.contains("Steam Workshop item 123456"));
        assert!(rendered.contains("detected suspicious content"));
        assert!(rendered.contains(r"C:\reports\mount-123456.json"));
        assert!(rendered.contains("closed before the map could load"));
    }

    #[test]
    fn rejects_untrusted_item_ids_and_decisions() {
        let bad_item = parse_options(&[
            "--item-id".into(),
            "1 & calc".into(),
            "--decision".into(),
            "block".into(),
            "--report".into(),
            "report.json".into(),
        ])
        .unwrap_err();
        assert!(bad_item.to_string().contains("only digits"));

        let bad_decision = parse_options(&[
            "--item-id".into(),
            "123".into(),
            "--decision".into(),
            "unknown".into(),
            "--report".into(),
            "report.json".into(),
        ])
        .unwrap_err();
        assert!(bad_decision.to_string().contains("--decision must be"));
    }
}
