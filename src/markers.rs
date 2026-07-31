use crate::model::MarkerEvidence;
use aho_corasick::AhoCorasick;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

const MAX_EVIDENCE_PER_MARKER: usize = 8;

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

pub struct MarkerScan {
    pub markers: BTreeSet<&'static str>,
    pub evidence: Vec<MarkerEvidence>,
}

impl MarkerScan {
    pub fn insert_metadata(&mut self, marker: &'static str, value: impl Into<String>) {
        self.markers.insert(marker);
        self.evidence.push(MarkerEvidence::metadata(marker, value));
        self.sort_evidence();
    }

    fn sort_evidence(&mut self) {
        self.evidence.sort();
    }
}

pub fn scan_markers(bytes: &[u8]) -> MarkerScan {
    let matcher = MATCHER.get_or_init(MarkerMatcher::new);
    let mut markers = BTreeSet::new();
    let mut evidence = Vec::new();
    let mut evidence_counts = BTreeMap::<&'static str, usize>::new();
    let mut raw_ip_url = None;
    for matched in matcher.automaton.find_overlapping_iter(bytes) {
        let metadata = &matcher.patterns[matched.pattern().as_usize()];
        markers.extend(metadata.markers.iter().copied());
        let matched_token = metadata
            .encoding
            .decode(&bytes[matched.start()..matched.end()]);
        let matched_value = if metadata.markers.contains("external-url") {
            url_value(bytes, matched.start(), matched.end(), metadata.encoding)
        } else {
            matched_token.clone()
        };
        for marker in &metadata.markers {
            let count = evidence_counts.entry(marker).or_default();
            if *count < MAX_EVIDENCE_PER_MARKER {
                evidence.push(MarkerEvidence::observed(
                    marker,
                    matched_value.clone(),
                    matched.start(),
                    metadata.encoding.label(),
                ));
                *count += 1;
            }
        }
        if raw_ip_url.is_none()
            && metadata.markers.contains("external-url")
            && let Some(host) = ipv4_host_after_url(bytes, matched.end(), metadata.encoding)
        {
            raw_ip_url = Some(MarkerEvidence::observed(
                "raw-ip-url",
                format!("{matched_token}{host}"),
                matched.start(),
                metadata.encoding.label(),
            ));
        }
    }
    if let Some(raw_ip_url) = raw_ip_url {
        markers.insert("raw-ip-url");
        evidence.push(raw_ip_url);
    }
    evidence.sort();
    MarkerScan { markers, evidence }
}

static MATCHER: OnceLock<MarkerMatcher> = OnceLock::new();

struct MarkerMatcher {
    automaton: AhoCorasick,
    patterns: Vec<PatternMetadata>,
}

impl MarkerMatcher {
    fn new() -> Self {
        let mut encoded = BTreeMap::<Vec<u8>, PatternMetadata>::new();
        for definition in MARKERS {
            for pattern in definition.patterns {
                for encoding in [
                    TextEncoding::Ascii,
                    TextEncoding::Utf16Le,
                    TextEncoding::Utf16Be,
                ] {
                    encoded
                        .entry(encoding.encode(pattern))
                        .or_insert_with(|| PatternMetadata {
                            markers: BTreeSet::new(),
                            encoding,
                        })
                        .markers
                        .insert(definition.name);
                }
            }
        }
        let (patterns, metadata): (Vec<_>, Vec<_>) = encoded.into_iter().unzip();
        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .expect("marker patterns are valid");
        Self {
            automaton,
            patterns: metadata,
        }
    }
}

struct PatternMetadata {
    markers: BTreeSet<&'static str>,
    encoding: TextEncoding,
}

#[derive(Clone, Copy)]
enum TextEncoding {
    Ascii,
    Utf16Le,
    Utf16Be,
}

impl TextEncoding {
    fn label(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Utf16Le => "utf-16le",
            Self::Utf16Be => "utf-16be",
        }
    }

    fn encode(self, text: &str) -> Vec<u8> {
        match self {
            Self::Ascii => text.as_bytes().to_vec(),
            Self::Utf16Le => text
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
            Self::Utf16Be => text
                .encode_utf16()
                .flat_map(u16::to_be_bytes)
                .collect::<Vec<_>>(),
        }
    }

    fn next_ascii(self, bytes: &[u8], offset: &mut usize) -> Option<u8> {
        match self {
            Self::Ascii => {
                let byte = *bytes.get(*offset)?;
                *offset += 1;
                Some(byte)
            }
            Self::Utf16Le => {
                let pair = bytes.get(*offset..*offset + 2)?;
                *offset += 2;
                (pair[1] == 0).then_some(pair[0])
            }
            Self::Utf16Be => {
                let pair = bytes.get(*offset..*offset + 2)?;
                *offset += 2;
                (pair[0] == 0).then_some(pair[1])
            }
        }
    }

    fn decode(self, bytes: &[u8]) -> String {
        match self {
            Self::Ascii => String::from_utf8_lossy(bytes).into_owned(),
            Self::Utf16Le | Self::Utf16Be => {
                let mut offset = 0;
                let mut decoded = String::with_capacity(bytes.len() / 2);
                while let Some(byte) = self.next_ascii(bytes, &mut offset) {
                    decoded.push(char::from(byte));
                }
                decoded
            }
        }
    }
}

fn url_value(bytes: &[u8], start: usize, mut offset: usize, encoding: TextEncoding) -> String {
    const MAX_URL_BYTES: usize = 256;

    let mut value = encoding.decode(&bytes[start..offset]);
    while value.len() < MAX_URL_BYTES
        && let Some(byte) = encoding.next_ascii(bytes, &mut offset)
    {
        if byte <= b' '
            || matches!(
                byte,
                0 | b'"' | b'\'' | b'`' | b'<' | b'>' | b'[' | b']' | b'{' | b'}'
            )
        {
            break;
        }
        value.push(char::from(byte));
    }
    value
}

fn ipv4_host_after_url(bytes: &[u8], mut offset: usize, encoding: TextEncoding) -> Option<String> {
    let mut host = [0_u8; 15];
    let mut length = 0;
    while let Some(byte) = encoding.next_ascii(bytes, &mut offset) {
        if matches!(
            byte,
            b'/' | b':' | b'\\' | b'?' | b'#' | b' ' | b'\r' | b'\n' | b'\t' | 0
        ) {
            break;
        }
        if length == host.len() || (!byte.is_ascii_digit() && byte != b'.') {
            return None;
        }
        host[length] = byte;
        length += 1;
    }
    let host = std::str::from_utf8(&host[..length]).unwrap_or_default();
    let mut octets = host.split('.');
    let valid = (0..4).all(|_| {
        octets.next().is_some_and(|octet| {
            !octet.is_empty()
                && octet.len() <= 3
                && octet.bytes().all(|byte| byte.is_ascii_digit())
                && octet.parse::<u8>().is_ok()
        })
    }) && octets.next().is_none();
    valid.then(|| host.to_owned())
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

        let scan = scan_markers(&bytes);
        assert!(scan.markers.contains("auto-execution"));
        assert!(scan.markers.contains("user-directory"));
        assert!(scan.markers.contains("file-write"));
        assert!(scan.markers.contains("process-shell"));
        assert!(scan.markers.contains("downloader"));
        assert!(scan.evidence.iter().any(|evidence| {
            evidence.marker == "downloader"
                && evidence.value == "Invoke-WebRequest"
                && evidence.encoding == "utf-16le"
                && evidence.byte_offset.is_some()
        }));
    }

    #[test]
    fn detects_guardian_inspired_command_families() {
        let scan = scan_markers(
            b"powershell -ExecutionPolicy Bypass -EncodedCommand AAAA \
              Start-BitsTransfer https://127.0.0.1/payload.cmd mshta.exe",
        );

        assert!(scan.markers.contains("policy-bypass"));
        assert!(scan.markers.contains("encoded-command"));
        assert!(scan.markers.contains("downloader"));
        assert!(scan.markers.contains("script-host"));
        assert!(scan.markers.contains("lolbin"));
        assert!(scan.markers.contains("raw-ip-url"));
        assert!(scan.evidence.iter().any(|evidence| {
            evidence.marker == "raw-ip-url" && evidence.value == "https://127.0.0.1"
        }));
        assert!(scan.evidence.iter().any(|evidence| {
            evidence.marker == "external-url" && evidence.value == "https://127.0.0.1/payload.cmd"
        }));
    }

    #[test]
    fn does_not_treat_domains_or_versions_as_raw_ip_urls() {
        assert!(
            !scan_markers(b"https://example.com/1.2.3.4")
                .markers
                .contains("raw-ip-url")
        );
    }

    #[test]
    fn bounds_repeated_evidence_per_marker() {
        let bytes = "powershell ".repeat(20);
        let scan = scan_markers(bytes.as_bytes());

        assert_eq!(
            scan.evidence
                .iter()
                .filter(|evidence| evidence.marker == "process-shell")
                .count(),
            MAX_EVIDENCE_PER_MARKER
        );
    }
}
