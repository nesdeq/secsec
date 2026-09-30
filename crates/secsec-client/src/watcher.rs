//! Filesystem watcher, the §10 commit-on-change trigger: a burst of events becomes one callback.

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Errors from the watcher.
#[derive(Debug)]
pub enum WatchError {
    /// The `notify` backend failed to start, or reported a failure (events may have been lost).
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

/// Watch `dir` recursively; call `on_change` (with the burst's first backend error) once per burst, after `debounce` of quiet or `max_delay`; `false` stops.
pub fn watch_dir<F>(
    dir: &Path,
    debounce: Duration,
    max_delay: Duration,
    mut on_change: F,
) -> Result<(), WatchError>
where
    F: FnMut(Option<WatchError>) -> bool,
{
    let (tx, rx) = mpsc::channel::<Option<notify::Error>>();
    let mut watcher: RecommendedWatcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let _ = tx.send(res.err());
        })?;
    watcher.watch(dir, RecursiveMode::Recursive)?;

    loop {
        let Ok(mut error) = rx.recv() else {
            return Ok(());
        };
        let started = Instant::now();
        loop {
            let left = max_delay.saturating_sub(started.elapsed());
            if left.is_zero() {
                break;
            }
            match rx.recv_timeout(debounce.min(left)) {
                Ok(e) => {
                    if error.is_none() {
                        error = e;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
        if !on_change(error.map(WatchError::Notify)) {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Wait up to `limit` for `count` to reach at least `want`.
    fn wait_for(count: &AtomicUsize, want: usize, limit: Duration) {
        let deadline = Instant::now() + limit;
        while count.load(Ordering::SeqCst) < want && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_burst_fires_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let fired = Arc::new(AtomicUsize::new(0));
        let f2 = fired.clone();
        let handle = std::thread::spawn(move || {
            watch_dir(
                &path,
                Duration::from_millis(80),
                Duration::from_secs(60),
                |_| {
                    f2.fetch_add(1, Ordering::SeqCst);
                    false
                },
            )
        });
        std::thread::sleep(Duration::from_millis(150));
        for i in 0..5 {
            std::fs::write(dir.path().join(format!("f{i}")), b"x").unwrap();
        }
        wait_for(&fired, 1, Duration::from_secs(10));
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        let _ = handle.join();
    }

    /// A never-quiet stream still fires once `max_delay` passes.
    #[test]
    fn a_continuous_stream_fires_by_max_delay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let fired = Arc::new(AtomicUsize::new(0));
        let f2 = fired.clone();
        let handle = std::thread::spawn(move || {
            watch_dir(
                &path,
                Duration::from_secs(30),
                Duration::from_millis(300),
                |_| {
                    f2.fetch_add(1, Ordering::SeqCst);
                    false
                },
            )
        });
        std::thread::sleep(Duration::from_millis(150));
        let writer_ends = Instant::now() + Duration::from_secs(10);
        let mut i = 0u64;
        while fired.load(Ordering::SeqCst) == 0 && Instant::now() < writer_ends {
            std::fs::write(dir.path().join("stream"), i.to_le_bytes()).unwrap();
            i += 1;
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "fired while events kept coming"
        );
        let _ = handle.join();
    }
}
