use crate::{
    markers::scan_markers,
    model::{Artifact, CompletenessReason, ScanCounts},
};
use anyhow::{Context, Result};
use rayon::prelude::*;
use retoc::{Config, iostore};
use std::{path::Path, sync::Arc};

struct ChunkScan {
    artifact: Option<Artifact>,
    scanned: bool,
    skipped_for_size: bool,
    reason: Option<CompletenessReason>,
}

pub fn scan_utocs(
    utocs: &[impl AsRef<Path>],
    max_chunk_bytes: u64,
) -> (Vec<Artifact>, ScanCounts, Vec<CompletenessReason>) {
    let mut artifacts = Vec::new();
    let mut counts = ScanCounts::default();
    let mut reasons = Vec::new();
    for utoc in utocs {
        let path = utoc.as_ref();
        match scan_utoc(path, max_chunk_bytes) {
            Ok((mut scanned_artifacts, scanned_counts, mut scanned_reasons)) => {
                artifacts.append(&mut scanned_artifacts);
                counts.chunks_seen += scanned_counts.chunks_seen;
                counts.chunks_scanned += scanned_counts.chunks_scanned;
                counts.chunks_skipped_for_size += scanned_counts.chunks_skipped_for_size;
                reasons.append(&mut scanned_reasons);
            }
            Err(error) => reasons.push(CompletenessReason {
                reason_id: "container-open-failed",
                phase: "container-read",
                summary: format!("{error:#}"),
                location: Some(path.display().to_string()),
            }),
        }
    }
    (artifacts, counts, reasons)
}

fn scan_utoc(
    path: &Path,
    max_chunk_bytes: u64,
) -> Result<(Vec<Artifact>, ScanCounts, Vec<CompletenessReason>)> {
    let store = iostore::open(path, Arc::new(Config::default()))
        .with_context(|| format!("retoc could not open {}", path.display()))?;
    let chunks = store.chunks().collect::<Vec<_>>();
    let prefix = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let scans = chunks
        .par_iter()
        .map(|chunk| {
            if chunk.size() == 0 {
                return ChunkScan {
                    artifact: None,
                    scanned: false,
                    skipped_for_size: false,
                    reason: None,
                };
            }
            let location = format!(
                "{prefix}::{}",
                chunk
                    .path()
                    .unwrap_or_else(|| format!("chunk:{:?}", chunk.id()))
            );
            if chunk.size() > max_chunk_bytes {
                return ChunkScan {
                    artifact: None,
                    scanned: false,
                    skipped_for_size: true,
                    reason: Some(CompletenessReason {
                        reason_id: "chunk-skipped-for-size",
                        phase: "container-read",
                        summary: format!(
                            "Chunk exceeds the configured {max_chunk_bytes} byte limit"
                        ),
                        location: Some(location),
                    }),
                };
            }
            match chunk.read() {
                Ok(bytes) => {
                    let markers = scan_markers(&bytes);
                    ChunkScan {
                        artifact: (!markers.is_empty()).then_some(Artifact {
                            location,
                            kind: "iostore-chunk",
                            size: chunk.size(),
                            sha256: None,
                            markers,
                        }),
                        scanned: true,
                        skipped_for_size: false,
                        reason: None,
                    }
                }
                Err(error) => ChunkScan {
                    artifact: None,
                    scanned: false,
                    skipped_for_size: false,
                    reason: Some(CompletenessReason {
                        reason_id: "chunk-read-failed",
                        phase: "container-read",
                        summary: format!("retoc could not read chunk: {error:#}"),
                        location: Some(location),
                    }),
                },
            }
        })
        .collect::<Vec<_>>();

    let mut artifacts = Vec::new();
    let mut counts = ScanCounts {
        chunks_seen: chunks.len(),
        ..ScanCounts::default()
    };
    let mut reasons = Vec::new();
    for scan in scans {
        counts.chunks_scanned += usize::from(scan.scanned);
        counts.chunks_skipped_for_size += usize::from(scan.skipped_for_size);
        artifacts.extend(scan.artifact);
        reasons.extend(scan.reason);
    }
    Ok((artifacts, counts, reasons))
}
