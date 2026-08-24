//! eitb — command-line demonstrator for the ITB Rust binding.
//!
//! Subcommands:
//!
//!   eitb version                                   library + binding versions
//!   eitb hashes                                    shipped hash primitive roster
//!   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
//!   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
//!
//! `encrypt` prints the session blob to stderr as hex; feed that hex
//! back to `decrypt` on the receiving side.

use std::ffi::{c_char, c_int};
use std::process::ExitCode;

use itb::{OptsBuilder, Pipeline};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("version") => cmd_version(),
        Some("hashes") => cmd_hashes(),
        Some("encrypt") if args.len() == 4 => cmd_encrypt(&args[1], &args[2], &args[3]),
        Some("decrypt") if args.len() == 5 => cmd_decrypt(&args[1], &args[2], &args[3], &args[4]),
        _ => {
            eprintln!(
                "usage: eitb version\n       eitb hashes\n       \
                 eitb encrypt <profile> <in-file> <out-file>\n       \
                 eitb decrypt <profile> <blob-hex> <in-file> <out-file>"
            );
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("eitb: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_version() -> Result<(), Box<dyn std::error::Error>> {
    println!("libitb {}", itb::version()?);
    println!("itb-rust {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}

/// Create the parent directory of `out` recursively (analogue of
/// `mkdir -p $(dirname out)`). Silent if the directory already
/// exists; propagates the error otherwise.
fn ensure_parent_dir(out: &str) -> std::io::Result<()> {
    if let Some(parent) = std::path::Path::new(out).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

/// Profiles whose canonical name begins with `streaming-` route
/// through the one-shot streaming buffered pair instead of the
/// Single Message pair.
fn is_streaming_profile(profile: &str) -> bool {
    profile.starts_with("streaming-")
}

fn cmd_encrypt(
    profile: &str,
    infile: &str,
    outfile: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let plain = std::fs::read(infile)?;
    let pipe = Pipeline::init(profile, &OptsBuilder::new())?;
    let wire = if is_streaming_profile(profile) {
        pipe.encrypt_stream_one_shot(&plain)?
    } else {
        pipe.encrypt_message(&plain)?
    };
    ensure_parent_dir(outfile)?;
    std::fs::write(outfile, &wire)?;
    eprintln!("{}", hex_encode(pipe.blob()));
    println!(
        "encrypted {} -> {} ({} -> {} bytes)",
        infile,
        outfile,
        plain.len(),
        wire.len()
    );
    Ok(())
}

fn cmd_decrypt(
    profile: &str,
    blob_hex: &str,
    infile: &str,
    outfile: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let blob = hex_decode(blob_hex)?;
    let wire = std::fs::read(infile)?;
    let pipe = Pipeline::open(profile, &blob, &OptsBuilder::new(), None)?;
    let plain = if is_streaming_profile(profile) {
        pipe.decrypt_stream_one_shot(&wire)?
    } else {
        pipe.decrypt_message(&wire)?
    };
    ensure_parent_dir(outfile)?;
    std::fs::write(outfile, &plain)?;
    println!(
        "decrypted {} -> {} ({} -> {} bytes)",
        infile,
        outfile,
        wire.len(),
        plain.len()
    );
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("blob hex has odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("blob hex: {e}")))
        .collect()
}

// ─── hashes — diagnostic registry iteration ────────────────────────
//
// The binding library deliberately exposes no primitive enumeration;
// this CLI diagnostic resolves the three iteration symbols itself so
// the shipped roster can be inspected from the shell. Loading the
// already-loaded shared library again only bumps the OS loader
// refcount.

type FnHashCount = unsafe extern "C" fn() -> c_int;
type FnHashName = unsafe extern "C" fn(c_int, *mut c_char, usize, *mut usize) -> c_int;
type FnHashWidth = unsafe extern "C" fn(c_int) -> c_int;

fn cmd_hashes() -> Result<(), Box<dyn std::error::Error>> {
    // Force the binding's own loader first so both paths resolve the
    // same library file.
    itb::version()?;
    // SAFETY: loading libitb (again) is idempotent at the OS loader.
    let lib = unsafe { libloading::Library::new(resolve_lib_path())? };
    // SAFETY (all three): symbol types match the libitb.h prototypes;
    // the Library stays alive for the whole function body.
    let count: libloading::Symbol<'_, FnHashCount> = unsafe { lib.get(b"ITB_HashCount")? };
    let name: libloading::Symbol<'_, FnHashName> = unsafe { lib.get(b"ITB_HashName")? };
    let width: libloading::Symbol<'_, FnHashWidth> = unsafe { lib.get(b"ITB_HashWidth")? };
    // SAFETY: value-out call.
    let n = unsafe { count() };
    for i in 0..n {
        let mut buf = vec![0u8; 128];
        let mut len = 0usize;
        // SAFETY: buf is writable for buf.len() bytes; len receives
        // the byte count written including the trailing NUL.
        let rc = unsafe { name(i, buf.as_mut_ptr().cast(), buf.len(), &mut len) };
        if rc != 0 {
            return Err(format!("ITB_HashName({i}) failed with status {rc}").into());
        }
        buf.truncate(len.saturating_sub(1));
        // SAFETY: value-out call.
        let w = unsafe { width(i) };
        println!("{:2}  {:<12} {} bits", i, String::from_utf8_lossy(&buf), w);
    }
    Ok(())
}

/// Mirrors the binding library's lookup order: `ITB_LIBITB_PATH` env,
/// then `<repo>/dist/<os>-<arch>/`, then the OS default loader path.
fn resolve_lib_path() -> std::path::PathBuf {
    let name = if cfg!(target_os = "windows") {
        "libitb.dll"
    } else if cfg!(target_os = "macos") {
        "libitb.dylib"
    } else {
        "libitb.so"
    };
    if let Ok(p) = std::env::var("ITB_LIBITB_PATH")
        && !p.is_empty()
    {
        return p.into();
    }
    let os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    let arch = if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        std::env::consts::ARCH
    };
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(repo) = manifest.ancestors().nth(3) {
        let cand = repo.join("dist").join(format!("{os}-{arch}")).join(name);
        if cand.is_file() {
            return cand;
        }
    }
    name.into()
}
