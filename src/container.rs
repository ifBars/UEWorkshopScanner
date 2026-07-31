use crate::{
    markers::scan_markers,
    model::{Artifact, CompletenessReason, ScanCounts},
};
use anyhow::{Context, Result};
use rayon::prelude::*;
use retoc::{Config, iostore};
use std::{path::Path, sync::Arc};

// Preserve parallel scanning for normal assets while preventing several large
// decoded chunks from occupying memory at the same time.
const PARALLEL_CHUNK_BYTES: u64 = 32 * 1024 * 1024;

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
    let mut scans = chunks
        .par_iter()
        .enumerate()
        .filter(|(_, chunk)| chunk.size() <= PARALLEL_CHUNK_BYTES)
        .map(|(index, chunk)| (index, scan_chunk(chunk, &prefix, max_chunk_bytes)))
        .collect::<Vec<_>>();
    scans.extend(
        chunks
            .iter()
            .enumerate()
            .filter(|(_, chunk)| chunk.size() > PARALLEL_CHUNK_BYTES)
            .map(|(index, chunk)| (index, scan_chunk(chunk, &prefix, max_chunk_bytes))),
    );
    scans.sort_unstable_by_key(|(index, _)| *index);

    let mut artifacts = Vec::new();
    let mut counts = ScanCounts {
        chunks_seen: chunks.len(),
        ..ScanCounts::default()
    };
    let mut reasons = Vec::new();
    for (_, scan) in scans {
        counts.chunks_scanned += usize::from(scan.scanned);
        counts.chunks_skipped_for_size += usize::from(scan.skipped_for_size);
        artifacts.extend(scan.artifact);
        reasons.extend(scan.reason);
    }
    Ok((artifacts, counts, reasons))
}

fn scan_chunk(chunk: &iostore::ChunkInfo<'_>, prefix: &str, max_chunk_bytes: u64) -> ChunkScan {
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
                    "Chunk is {} bytes ({:.1} MiB), above the configured {} byte ({:.1} MiB) limit",
                    chunk.size(),
                    bytes_to_mib(chunk.size()),
                    max_chunk_bytes,
                    bytes_to_mib(max_chunk_bytes)
                ),
                location: Some(location),
            }),
        };
    }
    match chunk.read() {
        Ok(bytes) => {
            let marker_scan = scan_markers(&bytes);
            ChunkScan {
                artifact: (!marker_scan.markers.is_empty()).then_some(Artifact {
                    location,
                    kind: "iostore-chunk",
                    size: chunk.size(),
                    sha256: None,
                    markers: marker_scan.markers,
                    evidence: marker_scan.evidence,
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
}

fn bytes_to_mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}
