//! Network-free replacement for retoc's Oodle loader.
//!
//! The upstream loader downloads a native library beside the executable when
//! one is missing. A security scanner must not do that. This adapter accepts
//! only an explicitly configured local library with an explicitly configured
//! SHA-256 digest.

use sha2::{Digest, Sha256};
use std::sync::OnceLock;

type Result<T, E = Error> = std::result::Result<T, E>;

pub use oodle_lz::{CompressionLevel, Compressor};

mod oodle_lz {
    #[derive(Debug, Clone, Copy)]
    #[repr(i32)]
    pub enum Compressor {
        None = 3,
        Kraken = 8,
        Leviathan = 13,
        Mermaid = 9,
        Selkie = 11,
        Hydra = 12,
    }

    #[derive(Debug, Clone, Copy)]
    #[repr(i32)]
    pub enum CompressionLevel {
        None = 0,
        SuperFast = 1,
        VeryFast = 2,
        Fast = 3,
        Normal = 4,
        Optimal1 = 5,
        Optimal2 = 6,
        Optimal3 = 7,
        Optimal4 = 8,
        Optimal5 = 9,
        HyperFast1 = -1,
        HyperFast2 = -2,
        HyperFast3 = -3,
        HyperFast4 = -4,
    }

    pub type Compress = unsafe extern "system" fn(
        compressor: Compressor,
        raw_buf: *const u8,
        raw_len: usize,
        comp_buf: *mut u8,
        level: CompressionLevel,
        options: *const (),
        dictionary_base: *const (),
        lrm: *const (),
        scratch_mem: *mut u8,
        scratch_size: usize,
    ) -> isize;

    pub type Decompress = unsafe extern "system" fn(
        comp_buf: *const u8,
        comp_buf_size: usize,
        raw_buf: *mut u8,
        raw_len: usize,
        fuzz_safe: u32,
        check_crc: u32,
        verbosity: u32,
        dec_buf_base: u64,
        dec_buf_size: usize,
        callback: u64,
        callback_user_data: u64,
        decoder_memory: *mut u8,
        decoder_memory_size: usize,
        thread_phase: u32,
    ) -> isize;

    pub type GetCompressedBufferSizeNeeded =
        unsafe extern "system" fn(compressor: Compressor, raw_size: usize) -> usize;
    pub type SetPrintf = unsafe extern "system" fn(printf: *const ());
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("UEWS_OODLE_PATH is not set; refusing retoc's network download path")]
    MissingPath,
    #[error("UEWS_OODLE_SHA256 is not set; an explicit decoder digest is required")]
    MissingDigest,
    #[error("Oodle decoder does not exist: {0}")]
    MissingFile(String),
    #[error("Oodle decoder SHA-256 mismatch; expected {expected}, got {found}")]
    HashMismatch { expected: String, found: String },
    #[error("Oodle compression failed")]
    CompressionFailed,
    #[error("Oodle initialization failed previously")]
    InitializationFailed,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Oodle library load error: {0}")]
    LibLoading(#[from] libloading::Error),
}

pub struct Oodle {
    _library: libloading::Library,
    compress: oodle_lz::Compress,
    decompress: oodle_lz::Decompress,
    get_compressed_buffer_size_needed: oodle_lz::GetCompressedBufferSizeNeeded,
    set_printf: oodle_lz::SetPrintf,
}

impl Oodle {
    fn new(library: libloading::Library) -> Result<Self> {
        // SAFETY: Symbol names and signatures are the stable Oodle Data ABI
        // consumed by retoc's upstream loader. The library remains owned by
        // this struct for at least as long as the resolved function pointers.
        unsafe {
            let result = Self {
                compress: *library.get(b"OodleLZ_Compress")?,
                decompress: *library.get(b"OodleLZ_Decompress")?,
                get_compressed_buffer_size_needed: *library
                    .get(b"OodleLZ_GetCompressedBufferSizeNeeded")?,
                set_printf: *library.get(b"OodleCore_Plugins_SetPrintf")?,
                _library: library,
            };
            (result.set_printf)(std::ptr::null());
            Ok(result)
        }
    }

    pub fn compress(
        &self,
        input: &[u8],
        compressor: Compressor,
        level: CompressionLevel,
    ) -> Result<Vec<u8>> {
        // SAFETY: Buffers are valid for their supplied lengths and Oodle owns
        // neither pointer after the call returns.
        unsafe {
            let capacity = (self.get_compressed_buffer_size_needed)(compressor, input.len());
            let mut output = vec![0; capacity];
            let length = (self.compress)(
                compressor,
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                level,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
            );
            if length == -1 {
                return Err(Error::CompressionFailed);
            }
            output.truncate(length as usize);
            Ok(output)
        }
    }

    pub fn decompress(&self, input: &[u8], output: &mut [u8]) -> isize {
        // SAFETY: Buffers are valid for their supplied lengths. Fuzz-safe and
        // CRC checking are enabled because the input is attacker controlled.
        unsafe {
            (self.decompress)(
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                output.len(),
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                0,
                3,
            )
        }
    }
}

static OODLE: OnceLock<Option<Oodle>> = OnceLock::new();

fn load_oodle() -> Result<Oodle> {
    let path = std::env::var_os("UEWS_OODLE_PATH").ok_or(Error::MissingPath)?;
    let path = std::path::PathBuf::from(path);
    if !path.is_file() {
        return Err(Error::MissingFile(path.display().to_string()));
    }

    let expected = std::env::var("UEWS_OODLE_SHA256")
        .map_err(|_| Error::MissingDigest)?
        .trim()
        .to_ascii_lowercase();
    let bytes = std::fs::read(&path)?;
    let found = hex::encode(Sha256::digest(&bytes));
    if expected != found {
        return Err(Error::HashMismatch { expected, found });
    }

    // SAFETY: The user-selected file was verified against the explicit digest
    // before loading. Symbol validation occurs in Oodle::new.
    let library = unsafe { libloading::Library::new(path)? };
    Oodle::new(library)
}

pub fn oodle() -> Result<&'static Oodle> {
    let mut first_error = None;
    let oodle = OODLE.get_or_init(|| match load_oodle() {
        Ok(value) => Some(value),
        Err(error) => {
            first_error = Some(error);
            None
        }
    });

    match (first_error, oodle) {
        (_, Some(oodle)) => Ok(oodle),
        (Some(error), _) => Err(error),
        _ => Err(Error::InitializationFailed),
    }
}
