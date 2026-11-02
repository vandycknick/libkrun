use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SETTINGS: &[&str] = &[
    "TARGET",
    "HOST",
    "OPT_LEVEL",
    "DEBUG",
    "PROFILE",
    "CARGO_CFG_TARGET_ARCH",
    "CARGO_CFG_TARGET_OS",
    "CARGO_CFG_TARGET_ENV",
    "CARGO_CFG_TARGET_ABI",
    "CARGO_CFG_TARGET_ENDIAN",
    "CARGO_CFG_TARGET_POINTER_WIDTH",
    "CARGO_CFG_TARGET_FEATURE",
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "MACOSX_DEPLOYMENT_TARGET",
    "SDKROOT",
];

pub fn emit() -> Result<(), Box<dyn Error>> {
    let mut output = String::new();
    writeln!(
        output,
        "/// Sorted package-local CARGO_FEATURE_* identifiers as supplied by Cargo."
    )?;
    let mut features: Vec<_> = env::vars_os()
        .filter_map(|(name, _)| name.into_string().ok())
        .filter(|name| name.starts_with("CARGO_FEATURE_"))
        .collect();
    features.sort();
    features.dedup();
    writeln!(
        output,
        "pub const FEATURES: Option<&[&str]> = Some(&{features:?});"
    )?;
    writeln!(
        output,
        "/// Observed inputs, not reconstructed effective compiler settings."
    )?;
    writeln!(output, "pub const SETTINGS: &[(&str, Option<&str>)] = &[")?;
    let mut settings_observed = true;
    for name in SETTINGS {
        println!("cargo:rerun-if-env-changed={name}");
        let value = match env::var(name) {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => {
                settings_observed = false;
                None
            }
        };
        writeln!(output, "({name:?}, {}),", option_literal(value.as_deref()))?;
    }
    writeln!(output, "];")?;
    writeln!(
        output,
        "/// False when an input could not be represented as UTF-8."
    )?;
    writeln!(
        output,
        "pub const SETTINGS_OBSERVED: bool = {settings_observed};"
    )?;
    writeln!(
        output,
        "/// Package name from this package's build environment."
    )?;
    writeln!(
        output,
        "pub const NAME: &str = {:?};",
        env::var("CARGO_PKG_NAME")?
    )?;
    writeln!(output, "/// Package version, not a native ABI revision.")?;
    writeln!(
        output,
        "pub const VERSION: &str = {:?};",
        env::var("CARGO_PKG_VERSION")?
    )?;
    writeln!(output, "/// Observed compilation target triple.")?;
    writeln!(
        output,
        "pub const TARGET: Option<&str> = {};",
        option_literal(env::var("TARGET").ok().as_deref())
    )?;
    let rustc = env::var_os("RUSTC").and_then(|rustc| {
        Command::new(rustc)
            .arg("-vV")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
    });
    writeln!(
        output,
        "/// Observed compiler version, including host and commit when available."
    )?;
    writeln!(
        output,
        "pub const RUSTC_VERSION: Option<&str> = {};",
        option_literal(rustc.as_deref())
    )?;
    writeln!(
        output,
        "include!(concat!(env!(\"OUT_DIR\"), \"/live_source.rs\"));"
    )?;
    println!("cargo:rerun-if-changed=../live_build.rs");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?).join("live_build.rs"),
        output,
    )?;
    emit_source()
}

fn emit_source() -> Result<(), Box<dyn Error>> {
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("missing CARGO_MANIFEST_DIR")?);
    let source_root = git(&manifest, &["rev-parse", "--show-toplevel"]);
    let root = source_root.as_ref().map(PathBuf::from).unwrap_or(manifest);
    let head = git(&root, &["rev-parse", "--verify", "HEAD"]);
    let status = git(
        &root,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    );
    let files = git(&root, &["ls-files", "-z"]);
    let metadata_paths = [
        "HEAD",
        "index",
        "packed-refs",
        "refs",
        "config",
        "info/exclude",
    ]
    .map(|name| {
        git(
            &root,
            &["rev-parse", "--path-format=absolute", "--git-path", name],
        )
    });
    let after = git(&root, &["rev-parse", "--verify", "HEAD"]);
    let state = match (&head, &status, &after) {
        (Some(head), Some(status), Some(after))
            if head == after && files.is_some() && metadata_paths.iter().all(Option::is_some) =>
        {
            if status.is_empty() {
                "Some(true)"
            } else {
                "Some(false)"
            }
        }
        _ => "None",
    };
    let output = format!(
        "/// Dependency-local Git root, if observable.\npub const SOURCE_ROOT: Option<&str> = {};\n/// Observed full HEAD, not necessarily a clean source identity.\npub const REVISION: Option<&str> = {};\n/// Clean, dirty, or unknown worktree at build-script execution.\npub const CLEAN: Option<bool> = {state};\n",
        option_literal(source_root.as_deref()),
        option_literal(head.as_deref()),
    );
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?).join("live_source.rs"),
        output,
    )?;

    // Watch source directories for new files as well as tracked modifications.
    for path in [
        "src",
        "init",
        "include",
        "Cargo.toml",
        "Cargo.lock",
        "Makefile",
        ".cargo",
        ".gitignore",
        "rust-toolchain",
        "rust-toolchain.toml",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
    if let Some(files) = files {
        for file in files.split('\0').filter(|file| !file.is_empty()) {
            println!("cargo:rerun-if-changed={}", root.join(file).display());
        }
    }
    for path in metadata_paths.into_iter().flatten() {
        println!("cargo:rerun-if-changed={path}");
    }
    Ok(())
}

fn option_literal(value: Option<&str>) -> String {
    match value {
        Some(value) => format!("Some({value:?})"),
        None => "None".to_owned(),
    }
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim_end_matches('\n').to_owned())
}
