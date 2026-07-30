use std::collections::BTreeSet;
use std::sync::OnceLock;

struct MarkerDefinition {
    name: &'static str,
    patterns: &'static [&'static str],
}

const MARKERS: &[MarkerDefinition] = &[
    MarkerDefinition {
        name: "auto-execution",
        patterns: &["ReceiveBeginPlay", "Event BeginPlay", "K2_ReceiveBeginPlay"],
    },
    MarkerDefinition {
        name: "launch-url",
        patterns: &["LaunchURL", "execLaunchURL", "Launch URL"],
    },
    MarkerDefinition {
        name: "local-file-scheme",
        patterns: &["file://", "file:\\\\", "steam://"],
    },
    MarkerDefinition {
        name: "user-directory",
        patterns: &[
            "GetPlatformUserDir",
            "GetUserDirectory",
            "Get User Directory",
            "GetTemporaryDirectory",
        ],
    },
    MarkerDefinition {
        name: "file-write",
        patterns: &[
            "ToFile",
            "Save Json to File",
            "SaveJsonToFile",
            "WriteFile",
            "SaveStringToFile",
            "SaveArrayToFile",
        ],
    },
    MarkerDefinition {
        name: "json-conversion",
        patterns: &["FromString", "JsonObject", "Json Blueprint Utilities"],
    },
    MarkerDefinition {
        name: "script-extension",
        patterns: &[
            ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".hta", ".wsf",
        ],
    },
    MarkerDefinition {
        name: "process-shell",
        patterns: &[
            "powershell",
            "pwsh",
            "cmd.exe",
            "cmd /c",
            "ShellExecute",
            "CreateProcess",
            "WinExec",
        ],
    },
    MarkerDefinition {
        name: "script-host",
        patterns: &["wscript.exe", "cscript.exe", "mshta.exe"],
    },
    MarkerDefinition {
        name: "lolbin",
        patterns: &[
            "mshta.exe",
            "regsvr32.exe",
            "rundll32.exe",
            "certutil.exe",
            "bitsadmin.exe",
        ],
    },
    MarkerDefinition {
        name: "downloader",
        patterns: &[
            "Invoke-WebRequest",
            "Invoke-RestMethod",
            "iwr ",
            "irm ",
            "DownloadString",
            "DownloadFile",
            "GetByteArrayAsync",
            "Start-BitsTransfer",
            "bitsadmin",
            "curl.exe",
            "wget.exe",
            "-OutFile",
        ],
    },
    MarkerDefinition {
        name: "hidden-execution",
        patterns: &[
            "-w hidden",
            "-WindowStyle Hidden",
            "start /min",
            "CreateNoWindow=true",
            "WindowStyle=Hidden",
        ],
    },
    MarkerDefinition {
        name: "policy-bypass",
        patterns: &[
            "-ep bypass",
            "-ExecutionPolicy Bypass",
            "ExecutionPolicy Bypass",
        ],
    },
    MarkerDefinition {
        name: "encoded-command",
        patterns: &["-EncodedCommand", "-enc ", "FromBase64String"],
    },
    MarkerDefinition {
        name: "base64-decode",
        patterns: &["FromBase64String", "Base64 Decode", "Decode Base64"],
    },
    MarkerDefinition {
        name: "polyglot-batch",
        patterns: &["if not defined", "%~f0", "&exit", "set _Z="],
    },
    MarkerDefinition {
        name: "external-url",
        patterns: &["http://", "https://"],
    },
    MarkerDefinition {
        name: "temp-directory",
        patterns: &[
            "$env:TEMP",
            "%TEMP%",
            "GetTempPath",
            "GetTemporaryDirectory",
        ],
    },
    MarkerDefinition {
        name: "historical-rce-name",
        patterns: &["BP_RCE_Test"],
    },
];

pub fn scan_markers(bytes: &[u8]) -> BTreeSet<&'static str> {
    let ascii = String::from_utf8_lossy(bytes).to_lowercase();
    let utf16_le_even = utf16_text(bytes, 0, true);
    let utf16_le_odd = utf16_text(bytes, 1, true);
    let utf16_be_even = utf16_text(bytes, 0, false);
    let utf16_be_odd = utf16_text(bytes, 1, false);
    let texts = [
        &*ascii,
        &utf16_le_even,
        &utf16_le_odd,
        &utf16_be_even,
        &utf16_be_odd,
    ];

    let normalized_patterns = NORMALIZED_PATTERNS.get_or_init(|| {
        MARKERS
            .iter()
            .map(|definition| {
                definition
                    .patterns
                    .iter()
                    .map(|pattern| pattern.to_ascii_lowercase())
                    .collect::<Vec<_>>()
            })
            .collect()
    });
    let mut markers = MARKERS
        .iter()
        .zip(normalized_patterns)
        .filter(|(_, patterns)| {
            patterns
                .iter()
                .any(|pattern| texts.iter().any(|text| text.contains(pattern)))
        })
        .map(|(definition, _)| definition.name)
        .collect::<BTreeSet<_>>();
    if markers.contains("external-url") && texts.iter().any(|text| contains_raw_ip_url(text)) {
        markers.insert("raw-ip-url");
    }
    markers
}

static NORMALIZED_PATTERNS: OnceLock<Vec<Vec<String>>> = OnceLock::new();

fn contains_raw_ip_url(text: &str) -> bool {
    ["http://", "https://"].into_iter().any(|scheme| {
        text.match_indices(scheme).any(|(start, _)| {
            let host = text[start + scheme.len()..]
                .split(['/', ':', '\\', '?', '#', ' ', '\r', '\n', '\t'])
                .next()
                .unwrap_or_default();
            let octets = host.split('.').collect::<Vec<_>>();
            octets.len() == 4
                && octets.iter().all(|octet| {
                    !octet.is_empty()
                        && octet.chars().all(|character| character.is_ascii_digit())
                        && octet.parse::<u8>().is_ok()
                })
        })
    })
}

fn utf16_text(bytes: &[u8], offset: usize, little_endian: bool) -> String {
    let units = bytes
        .get(offset..)
        .unwrap_or_default()
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&units).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ascii_and_unaligned_utf16_markers() {
        let mut bytes = b"ReceiveBeginPlay GetPlatformUserDir ".to_vec();
        bytes.push(0xff);
        for unit in "ToFile powershell Invoke-WebRequest".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }

        let markers = scan_markers(&bytes);
        assert!(markers.contains("auto-execution"));
        assert!(markers.contains("user-directory"));
        assert!(markers.contains("file-write"));
        assert!(markers.contains("process-shell"));
        assert!(markers.contains("downloader"));
    }

    #[test]
    fn detects_guardian_inspired_command_families() {
        let markers = scan_markers(
            b"powershell -ExecutionPolicy Bypass -EncodedCommand AAAA \
              Start-BitsTransfer https://127.0.0.1/payload.cmd mshta.exe",
        );

        assert!(markers.contains("policy-bypass"));
        assert!(markers.contains("encoded-command"));
        assert!(markers.contains("downloader"));
        assert!(markers.contains("script-host"));
        assert!(markers.contains("lolbin"));
        assert!(markers.contains("raw-ip-url"));
    }

    #[test]
    fn does_not_treat_domains_or_versions_as_raw_ip_urls() {
        assert!(!scan_markers(b"https://example.com/1.2.3.4").contains("raw-ip-url"));
    }
}
