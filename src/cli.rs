use crate::{
    game_profile::{built_in_game_profiles, game_profile},
    oodle,
    output::{OutputFormat, format_summary},
    scanner::{OodleDecoder, Scanner, ScannerOptions},
};
use anyhow::{Context, Result, bail};
use std::{ffi::OsString, path::PathBuf};

#[derive(Debug)]
struct Options {
    input: PathBuf,
    oodle_path: Option<PathBuf>,
    oodle_sha256: Option<String>,
    max_item_bytes: u64,
    accept_eula: bool,
    game: Option<String>,
    output: Option<PathBuf>,
    output_format: OutputFormat,
}

pub(crate) fn run(args: Vec<OsString>) -> Result<i32> {
    if args
        .first()
        .is_some_and(|argument| argument == "--notify-block")
    {
        return crate::notification::run(&args[1..]);
    }
    if args
        .first()
        .is_some_and(|argument| argument == "--integration-setup")
    {
        return crate::integration_setup::run(&args[1..]);
    }
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
    if args.len() == 1 && args[0] == "--accept-eula" {
        oodle::accept_bundled_eula()?;
        println!("Bundled binary terms accepted.");
        return Ok(0);
    }
    if args.iter().any(|argument| argument == "--list-games") {
        for profile in built_in_game_profiles()? {
            println!(
                "{}\t{}\tSteam App ID {}",
                profile.id, profile.name, profile.steam_app_id
            );
        }
        return Ok(0);
    }

    let options = parse_options(args)?;
    let selected_profile = match options.game.as_deref() {
        Some(id) => Some(
            game_profile(id)?
                .with_context(|| format!("unknown game profile: {id}; use --list-games"))?,
        ),
        None => None,
    };
    let oodle_decoder = match (options.oodle_path, options.oodle_sha256) {
        (Some(path), Some(sha256)) => Some(OodleDecoder::new(path, sha256)),
        (None, None) => None,
        _ => bail!("--oodle-path and --oodle-sha256 must be supplied together"),
    };
    let scanner = Scanner::new(ScannerOptions {
        max_item_bytes: options.max_item_bytes,
        game_profile: selected_profile,
        oodle_decoder,
        accept_bundled_eula: options.accept_eula,
    })?;
    let report = scanner.scan(&options.input)?;
    let exit_code = match report.verdict {
        "allow" => 0,
        "review" => 2,
        "block" => 3,
        _ => 4,
    };
    let rendered = match options.output_format {
        OutputFormat::Json => serde_json::to_string_pretty(&report)?,
        OutputFormat::Summary => format_summary(&report),
    };
    if let Some(output) = options.output {
        if let Some(parent) = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        std::fs::write(&output, format!("{}\n", rendered.trim_end()))
            .with_context(|| format!("could not write {}", output.display()))?;
    } else {
        println!("{}", rendered.trim_end());
    }
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
    let mut game = None;
    let mut output = None;
    let mut output_format = OutputFormat::Json;
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
            "--game" => {
                game = Some(
                    args.next()
                        .context("--game needs a value")?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            "--output" => {
                output = Some(PathBuf::from(
                    args.next().context("--output needs a value")?,
                ));
            }
            "--format" => {
                output_format = OutputFormat::parse(
                    &args
                        .next()
                        .context("--format needs a value")?
                        .to_string_lossy(),
                )?;
            }
            "--summary" => output_format = OutputFormat::Summary,
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
        game,
        output,
        output_format,
    })
}

fn print_help() {
    println!(
        "UEWorkshopScanner {}\n\
         Static malware scanner for Unreal Engine Workshop content.\n\n\
         Usage:\n  \
           ue-workshop-scanner <file.utoc|directory> [options]\n  \
           ue-workshop-scanner --accept-eula\n  \
           ue-workshop-scanner --licenses\n\n\
         Options:\n  \
           --max-item-mb <n>        Per-file/chunk scan cap (1-2048, default 32)\n  \
           --max-chunk-mb <n>       Backward-compatible alias for --max-item-mb\n  \
           --oodle-path <dll>       Explicit Oodle decoder path\n  \
           --oodle-sha256 <hex>     Required digest for an explicit decoder\n  \
           --accept-eula            Accept the bundled binary EULA non-interactively\n  \
           --game <profile-id>      Include a supported game profile in the report\n  \
           --list-games             List embedded game profiles\n  \
           --output <path>          Write the selected report to a file\n  \
           --format <json|summary>  Select machine or human-readable output\n  \
           --summary                Shortcut for --format summary\n  \
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
        assert!(options.game.is_none());
        assert!(options.output.is_none());
        assert_eq!(options.output_format, OutputFormat::Json);
    }

    #[test]
    fn requires_oodle_path_and_digest_as_a_pair() {
        let error = run(vec![
            "fixture".into(),
            "--oodle-path".into(),
            "decoder.dll".into(),
        ])
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("--oodle-path and --oodle-sha256")
        );
    }
}
