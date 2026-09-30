//! `cargo xtask`: `vectors [--check]` recomputes the KAT file from live code; `release` prints the reproducible build (`secsec-Implementation.md` §3, `secsec-Design.md` §18).

#![allow(missing_docs)] // a binary crate has no public API

use std::process::ExitCode;

mod vectors;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("vectors") => {
            let check = args.iter().any(|a| a == "--check");
            match vectors::run(check) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("xtask vectors: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("release") => {
            release_help();
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: cargo xtask <vectors [--check] | release>");
            ExitCode::FAILURE
        }
    }
}

/// Print the reproducible static-musl release recipe (`secsec-Design.md` §18) rather than running it, so it stays inspectable.
fn release_help() {
    println!(
        "reproducible static release (secsec-Design.md §18):\n\
         \n\
         # one-time:\n\
         rustup target add x86_64-unknown-linux-musl\n\
         \n\
         # deterministic build (the release profile pins panic=abort and overflow-checks):\n\
         SOURCE_DATE_EPOCH=0 \\\n\
         RUSTFLAGS=\"-C target-feature=+crt-static --remap-path-prefix=$PWD=. -C link-arg=-s\" \\\n\
         cargo build --release --locked --bin secsec --target x86_64-unknown-linux-musl\n\
         \n\
         # the artifact is one static binary:\n\
         #   target/x86_64-unknown-linux-musl/release/secsec\n\
         # verify reproducibility by building twice and comparing sha256."
    );
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    /// Every workspace member inherits `[lints] workspace = true`, which is what applies `unsafe_code = forbid` and the lint levels.
    #[test]
    fn every_workspace_member_inherits_the_workspace_lints() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
        let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("root manifest");
        let array = manifest
            .split_once("members")
            .and_then(|(_, rest)| rest.split_once('['))
            .and_then(|(_, rest)| rest.split_once(']'))
            .map(|(inner, _)| inner)
            .expect("workspace.members array");
        let members: Vec<&str> = array
            .split(',')
            .map(|m| m.trim().trim_matches('"'))
            .filter(|m| !m.is_empty())
            .collect();
        assert!(members.len() > 10, "parsed too few members: {members:?}");

        for member in members {
            let path = root.join(member).join("Cargo.toml");
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let after = text
                .split_once("[lints]")
                .unwrap_or_else(|| panic!("{member} has no [lints] section"))
                .1;
            // Only up to the next section header, so a later table cannot satisfy the check.
            let section = after.split_once("\n[").map_or(after, |(head, _)| head);
            assert!(
                section.contains("workspace = true"),
                "{member} does not inherit the workspace lints"
            );
        }
    }
}
