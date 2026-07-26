//! `xtask` — build tooling (`secsec-Design.md` §3, §20).
//!
//! - `cargo xtask vectors` regenerates `vectors/secsec-kat-v1.txt` **mechanically** from the same code
//!   paths the inline KAT `#[test]`s assert, so the human/cross-impl export can never drift from the
//!   code. `cargo xtask vectors --check` regenerates in memory and fails if the committed file differs
//!   (CI guard).
//! - `cargo xtask release` prints/runs the reproducible static-`musl` release build (§20): pinned
//!   target, deterministic flags, `panic=abort` + overflow-checks from the workspace release profile.

#![allow(missing_docs)] // a binary crate exports no public API

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

/// Print the reproducible static-musl release recipe (§20). Kept as instructions rather than shelling
/// out, so it is inspectable and works regardless of the host toolchain.
fn release_help() {
    println!(
        "reproducible static release (§20):\n\
         \n\
         # one-time:\n\
         rustup target add x86_64-unknown-linux-musl\n\
         \n\
         # deterministic build (release profile pins panic=abort + overflow-checks):\n\
         SOURCE_DATE_EPOCH=0 \\\n\
         RUSTFLAGS='-C target-feature=+crt-static --remap-path-prefix=$PWD=. -C link-arg=-s' \\\n\
         cargo build --release --locked --bin secsec --target x86_64-unknown-linux-musl\n\
         \n\
         # the artifact is a single static binary:\n\
         #   target/x86_64-unknown-linux-musl/release/secsec\n\
         # verify reproducibility by building twice and comparing sha256."
    );
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    /// Every workspace member must carry `[lints] workspace = true`. That inheritance is what actually
    /// applies `unsafe_code = "forbid"`, `unreachable_pub` and `clippy::all = deny` to a crate; a new
    /// member that omits it silently opts out of all three, and nothing else in the build would notice.
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
            .filter_map(|m| m.trim().trim_matches('"').into())
            .filter(|m: &&str| !m.is_empty())
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
            // Only look as far as the next section header, so a later table cannot satisfy this.
            let section = after.split_once("\n[").map_or(after, |(head, _)| head);
            assert!(
                section.contains("workspace = true"),
                "{member} does not inherit the workspace lints"
            );
        }
    }
}
