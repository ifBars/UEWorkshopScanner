use crate::{hashing::sha256_file, notification, oodle};
use anyhow::{Context, Result, bail};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
};

const MECCHA_VERSION: &str = "3.1.0";
const MECCHA_EXE_SHA256: &str = "001b329edb0f37b6d3157d8334edbd58a83d092d9748f9439dd1b59f2cace36a";
const UE4SS_VERSION: &str = "3.0.1 Beta #0 (Git 0196ef29)";
const UE4SS_DLL_SHA256: &str = "df9e6e9a2280972b1c28ce590700feacc752b447204f8baadeb95f5776957055";

#[derive(Debug, PartialEq, Eq)]
struct Options {
    game_exe: PathBuf,
    ue4ss_dll: PathBuf,
}

pub(crate) fn run(args: &[OsString]) -> Result<i32> {
    match run_inner(args) {
        Ok(exit_code) => Ok(exit_code),
        Err(error) => {
            notification::show_warning(
                "UEWorkshopScanner setup failed",
                &format!(
                    "Automatic Workshop protection was not enabled.\n\n{error:#}\n\n\
                     Restart the game to try setup again. If the problem continues, include the integration-setup.log file when reporting it."
                ),
            )?;
            Ok(4)
        }
    }
}

fn run_inner(args: &[OsString]) -> Result<i32> {
    let options = parse_options(args)?;
    if let Err(error) = verify_compatibility(&options) {
        notification::show_warning(
            "UEWorkshopScanner compatibility warning",
            &format!(
                "Automatic Workshop protection was not enabled.\n\n{error:#}\n\n\
                 Supported game: MECCHA CHAMELEON {MECCHA_VERSION}\n\
                 Supported UE4SS: {UE4SS_VERSION}\n\n\
                 Update UEWorkshopScanner before using it with a different game or loader build."
            ),
        )?;
        return Ok(4);
    }

    if oodle::bundled_eula_is_accepted()? {
        oodle::verify_bundled_distribution(false)?;
        return Ok(0);
    }

    let eula_path = oodle::bundled_eula_path()?;
    notification::show_information(
        "UEWorkshopScanner first-time setup",
        "Automatic Workshop protection needs one-time acceptance of the bundled binary terms.\n\n\
         The complete agreement will open in Notepad. Read it, close Notepad, then choose whether to accept.\n\n\
         Protection stays inactive until setup finishes.",
    )?;
    open_eula(&eula_path)?;

    let accepted = notification::confirm(
        "Accept UEWorkshopScanner binary terms?",
        "Do you accept the UEWorkshopScanner Binary EULA?\n\n\
         The scanner is experimental. It can miss malware, report safe content as suspicious, or return an incomplete result. \
         It does not replace antivirus software or backups.\n\n\
         Choose Yes to record acceptance and enable automatic protection. Choose No to leave protection disabled.",
    )?;
    if !accepted {
        notification::show_warning(
            "UEWorkshopScanner protection is inactive",
            "The binary terms were not accepted, so automatic Workshop protection was not enabled.\n\n\
             You can run the setup again by restarting the game.",
        )?;
        return Ok(4);
    }

    oodle::verify_bundled_distribution(true)?;
    notification::show_information(
        "UEWorkshopScanner setup complete",
        "The binary terms were accepted. Automatic Workshop protection will now activate.",
    )?;
    Ok(0)
}

fn parse_options(args: &[OsString]) -> Result<Options> {
    let mut arguments = args.iter();
    let mut game_exe = None;
    let mut ue4ss_dll = None;

    while let Some(argument) = arguments.next() {
        match argument.to_string_lossy().as_ref() {
            "--game-exe" => {
                game_exe = Some(PathBuf::from(
                    arguments.next().context("--game-exe needs a value")?,
                ));
            }
            "--ue4ss-dll" => {
                ue4ss_dll = Some(PathBuf::from(
                    arguments.next().context("--ue4ss-dll needs a value")?,
                ));
            }
            unknown => bail!("unknown integration setup argument: {unknown}"),
        }
    }

    Ok(Options {
        game_exe: game_exe.context("--integration-setup requires --game-exe")?,
        ue4ss_dll: ue4ss_dll.context("--integration-setup requires --ue4ss-dll")?,
    })
}

fn verify_compatibility(options: &Options) -> Result<()> {
    verify_file(
        "MECCHA CHAMELEON executable",
        &options.game_exe,
        MECCHA_EXE_SHA256,
    )?;
    verify_file("UE4SS.dll", &options.ue4ss_dll, UE4SS_DLL_SHA256)?;
    Ok(())
}

fn verify_file(label: &str, path: &Path, expected: &str) -> Result<()> {
    if !path.is_file() {
        bail!("{label} was not found at {}", path.display());
    }
    let actual = sha256_file(path)?;
    if !actual.eq_ignore_ascii_case(expected) {
        bail!(
            "{label} does not match the tested build.\nExpected SHA-256: {expected}\nActual SHA-256:   {actual}"
        );
    }
    Ok(())
}

fn open_eula(path: &Path) -> Result<()> {
    let status = Command::new("notepad.exe")
        .arg(path)
        .status()
        .with_context(|| format!("could not open {} in Notepad", path.display()))?;
    if !status.success() {
        bail!("Notepad exited before the agreement could be reviewed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_compatibility_inputs() {
        let options = parse_options(&[
            "--game-exe".into(),
            "game.exe".into(),
            "--ue4ss-dll".into(),
            "UE4SS.dll".into(),
        ])
        .unwrap();

        assert_eq!(options.game_exe, PathBuf::from("game.exe"));
        assert_eq!(options.ue4ss_dll, PathBuf::from("UE4SS.dll"));
    }

    #[test]
    fn reports_a_missing_compatibility_file() {
        let missing = std::env::temp_dir().join(format!(
            "uews-missing-compatibility-file-{}",
            std::process::id()
        ));
        let error = verify_file("test file", &missing, "00").unwrap_err();
        assert!(error.to_string().contains("was not found"));
    }
}
