use crate::{oodle, scanner};
use anyhow::{Context, Result, bail};
use std::{ffi::OsString, path::PathBuf};

#[derive(Debug)]
struct Options {
    input: PathBuf,
    oodle_path: Option<PathBuf>,
    oodle_sha256: Option<String>,
    max_item_bytes: u64,
    accept_eula: bool,
}

pub(crate) fn run(args: Vec<OsString>) -> Result<i32> {
    if args.is_empty()
        || args
            .iter()
            .any(|argument| argument == "--help" || argument == "-h")
    {
        print_help();
        return Ok(0);
    }
    if args
        .iter()
        .any(|argument| argument == "--version" || argument == "-V")
    {
        println!("ue-workshop-scanner {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    if args.iter().any(|argument| argument == "--licenses") {
        oodle::print_licenses();
        return Ok(0);
    }

    let options = parse_options(args)?;
    oodle::configure(
        options.oodle_path.as_deref(),
        options.oodle_sha256.as_deref(),
        options.accept_eula,
    )?;

    let report = scanner::scan(&options.input, options.max_item_bytes)?;
    let exit_code = match report.verdict {
        "allow" => 0,
        "review" => 2,
        "block" => 3,
        _ => 4,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(exit_code)
}

fn parse_options(args: Vec<OsString>) -> Result<Options> {
    let mut args = args.into_iter();
    let input = args.next().map(PathBuf::from).context(
        "usage: ue-workshop-scanner <file.utoc|directory> [--oodle-path <dll> --oodle-sha256 <hex>] [--max-item-mb <n>] [--accept-eula]",
    )?;
    let mut oodle_path = None;
    let mut oodle_sha256 = None;
    let mut max_item_bytes = 32 * 1024 * 1024;
    let mut accept_eula = false;
    while let Some(argument) = args.next() {
        match argument.to_string_lossy().as_ref() {
            "--oodle-path" => {
                oodle_path = Some(PathBuf::from(
                    args.next().context("--oodle-path needs a value")?,
                ));
            }
            "--oodle-sha256" => {
                oodle_sha256 = Some(
                    args.next()
                        .context("--oodle-sha256 needs a value")?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            "--max-item-mb" | "--max-chunk-mb" => {
                let value = args
                    .next()
                    .context("--max-item-mb needs a value")?
                    .to_string_lossy()
                    .parse::<u64>()
                    .context("--max-item-mb must be an integer")?;
                if !(1..=2048).contains(&value) {
                    bail!("--max-item-mb must be between 1 and 2048");
                }
                max_item_bytes = value * 1024 * 1024;
            }
            "--accept-eula" => accept_eula = true,
            "--licenses" => unreachable!("handled before option parsing"),
            unknown => bail!("unknown argument: {unknown}"),
        }
    }
    Ok(Options {
        input,
        oodle_path,
        oodle_sha256,
        max_item_bytes,
        accept_eula,
    })
}

fn print_help() {
    println!(
        "UEWorkshopScanner {}\n\
         Static malware scanner for Unreal Engine Workshop content.\n\n\
         Usage:\n  \
           ue-workshop-scanner <file.utoc|directory> [options]\n  \
           ue-workshop-scanner --licenses\n\n\
         Options:\n  \
           --max-item-mb <n>        Per-file/chunk scan cap (1-2048, default 32)\n  \
           --max-chunk-mb <n>       Backward-compatible alias for --max-item-mb\n  \
           --oodle-path <dll>       Explicit Oodle decoder path\n  \
           --oodle-sha256 <hex>     Required digest for an explicit decoder\n  \
           --accept-eula            Accept the bundled binary EULA non-interactively\n  \
           --licenses               Print source license, binary EULA, and notices\n  \
           -h, --help               Print help\n  \
           -V, --version            Print version\n\n\
         Exit codes:\n  \
           0 allow     2 review     3 block     4 incomplete/error",
        env!("CARGO_PKG_VERSION")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_directory_and_legacy_size_alias() {
        let options = parse_options(vec![
            "fixture".into(),
            "--max-chunk-mb".into(),
            "64".into(),
            "--accept-eula".into(),
        ])
        .unwrap();

        assert_eq!(options.input, PathBuf::from("fixture"));
        assert_eq!(options.max_item_bytes, 64 * 1024 * 1024);
        assert!(options.accept_eula);
    }

    #[test]
    fn requires_oodle_path_and_digest_as_a_pair() {
        let options = parse_options(vec![
            "fixture".into(),
            "--oodle-path".into(),
            "decoder.dll".into(),
        ])
        .unwrap();

        let error = oodle::configure(
            options.oodle_path.as_deref(),
            options.oodle_sha256.as_deref(),
            false,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("--oodle-path and --oodle-sha256")
        );
    }
}
