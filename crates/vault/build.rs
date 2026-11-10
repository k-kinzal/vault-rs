use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            walk(root, &path, out);
        } else if entry.file_type().unwrap().is_file() {
            let relative = path.strip_prefix(root).unwrap();
            if !relative
                .components()
                .any(|p| p.as_os_str() == "__pycache__")
            {
                out.push(path);
            }
        }
    }
}
fn main() {
    // Restrict this to the shipped Mach-O executable. Applying it globally to
    // host proc-macro dylibs prevents rustc from loading those compiler plugins.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg-bin=vault-rs=-Wl,-no_uuid");
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut files = Vec::new();
    for dir in [
        "crates", "formal", "platform", "scripts", "docs", "vendor", "tools", "examples", ".github",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(dir).display());
        walk(&root, &root.join(dir), &mut files);
    }
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "README.md",
    ] {
        files.push(root.join(name));
    }
    files.sort();
    let mut hash = Sha256::new();
    for path in files {
        let name = path
            .strip_prefix(&root)
            .unwrap()
            .to_str()
            .unwrap()
            .as_bytes();
        let bytes = fs::read(&path).unwrap();
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name);
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let value: String = hash.finalize().iter().map(|v| format!("{v:02x}")).collect();
    println!("cargo:rustc-env=VAULT_SOURCE_SHA256={value}");
}
