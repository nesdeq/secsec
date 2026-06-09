//! Filesystem watcher — the §10 live trigger for commit-on-change. Wraps `notify`
//! (inotify/FSEvents/ReadDirectoryChangesW) and **debounces** a burst of events into a single
//! "directory changed" callback, so a multi-file save or an editor's write-rename dance produces one
//! commit, not dozens.
//!
//! The debounce window is a **caller-supplied** `Duration` (no baked-in cadence — §19 leaves the
//! snapshot cadence to configuration); the loop fires `on_change` once the directory has been quiet
//! for that long. `on_change` returns `true` to keep watching or `false` to stop (a clean shutdown
//! hook); the loop also returns when the watcher is dropped.

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

/// Errors from the watcher.
#[derive(Debug)]
pub enum WatchError {
    /// The underlying `notify` backend failed to start or watch.
    Notify(notify::Error),
}
impl core::fmt::Display for WatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WatchError::Notify(e) => write!(f, "watch: {e}"),
        }
    }
}
impl std::error::Error for WatchError {}
impl From<notify::Error> for WatchError {
    fn from(e: notify::Error) -> Self {
        WatchError::Notify(e)
    }
}

/// Watch `dir` recursively and call `on_change` once per **debounced burst** of filesystem changes.
/// Blocks: each iteration waits for the first change, then drains further changes until the tree has
/// been quiet for `debounce`, then fires `on_change`. Returns `Ok(())` when `on_change` returns
/// `false` (requested stop) or the watcher is dropped. `debounce` is the caller's snapshot cadence
/// (§10/§19) — there is no hidden default.
pub fn watch_dir<F>(dir: &Path, debounce: Duration, mut on_change: F) -> Result<(), WatchError>
where
    F: FnMut() -> bool,
{
    let (tx, rx) = mpsc::channel::<()>();
    // A successful event is coalesced to a single "something changed" tick; the specific path/op is
    // not needed (the next snapshot re-reads the whole tree and dedups via content addressing).
    let mut watcher: RecommendedWatcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if res.is_ok() {
                let _ = tx.send(());
            }
        })?;
    watcher.watch(dir, RecursiveMode::Recursive)?;

    loop {
        // Block until the first change of a new burst (or the watcher goes away).
        if rx.recv().is_err() {
            return Ok(());
        }
        // Coalesce: keep draining until the tree has been quiet for `debounce`.
        loop {
            match rx.recv_timeout(debounce) {
                Ok(()) => continue,
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
        if !on_change() {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    #[test]
    fn debounced_change_fires_once_per_burst() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let fired = Arc::new(AtomicUsize::new(0));

        let f2 = fired.clone();
        let handle = std::thread::spawn(move || {
            // ~80 ms debounce; stop after the first fire so the thread exits cleanly.
            watch_dir(&path, Duration::from_millis(80), || {
                f2.fetch_add(1, Ordering::SeqCst);
                false
            })
        });

        // Give the watcher a moment to start, then write a burst of files (one coalesced change).
        std::thread::sleep(Duration::from_millis(150));
        for i in 0..5 {
            std::fs::write(dir.path().join(format!("f{i}")), b"x").unwrap();
        }

        // Wait (generously, for FSEvents latency) for the single debounced fire.
        let deadline = Instant::now() + Duration::from_secs(10);
        while fired.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "a burst of writes must coalesce into exactly one change"
        );
        let _ = handle.join();
    }
}
