// src/policy/watcher.rs
//! File-system watcher for hot-reloading `rules.yaml` without restarting RUBIX.
//!
//! ── Design ────────────────────────────────────────────────────────────────
//!
//! `PolicyWatcher` wraps the `notify` crate's `RecommendedWatcher`, which
//! uses the best available OS primitive on each platform:
//!
//!   Linux   → inotify(7)         (kernel-level, zero polling)
//!   Windows → ReadDirectoryChangesW  (Win32, kernel-level, zero polling)
//!   macOS   → FSEvents / kqueue  (not a target but works anyway)
//!
//! No platform-specific code is required here because `notify` already
//! isolates it.  This keeps the watcher fully cross-platform with a single
//! implementation file, consistent with the architecture constraint that
//! platform differences are isolated inside the library that owns them.
//!
//! ── Debounce ──────────────────────────────────────────────────────────────
//!
//! Most editors (vim, VSCode, nano) perform multiple write(2) / rename(2)
//! syscalls per save.  Without debouncing, one logical save triggers 3-10
//! `Modify` events in rapid succession, each firing a full rule parse.
//!
//! Strategy: the notify callback sends a unit signal over a bounded
//! `tokio::sync::mpsc` channel (capacity 1 — extra signals collapse).  A
//! Tokio task drains the channel and waits `DEBOUNCE_MS` after the LAST
//! signal before calling `reloader.reload()`.  This means:
//!
//!   • 1 logical save    → exactly 1 reload (after silence period)
//!   • Rapid saves       → 1 reload per burst (last write wins)
//!   • No timer resets   → reload never delayed more than DEBOUNCE_MS past
//!                         the final write event
//!
//! ── Lifecycle ─────────────────────────────────────────────────────────────
//!
//! `PolicyWatcher::start()` spawns a detached Tokio task.  The task holds an
//! `Arc<PolicyReloader>` and runs until the process exits.  The
//! `RecommendedWatcher` is kept alive inside the task via a `_watcher` binding
//! — dropping it would unregister the OS watch.
//!
//! ── Error handling ────────────────────────────────────────────────────────
//!
//! • If the initial watch registration fails (path doesn't exist, permission
//!   denied), `start()` returns `Err` immediately.  The caller (main.rs)
//!   decides whether to abort or continue without hot-reload.
//!
//! • If `reloader.reload()` fails (parse error, I/O error), the error is
//!   logged as `warn!` and the previous rule set remains active.  RUBIX
//!   never drops to zero rules due to a bad save.
//!
//! • Notify errors emitted after startup (e.g. watch handle invalidated) are
//!   logged as `error!` but do not crash the task.

use super::PolicyReloader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use notify::{RecommendedWatcher, RecursiveMode, Watcher, EventKind};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{info, warn, error, debug};
use anyhow::{Result, Context};

// ── Tuning constants ──────────────────────────────────────────────────────────

/// Silence window after the last file-system event before reload fires.
/// 500 ms covers all common editor save patterns (vim swapfile rename,
/// VSCode atomic write, nano tmp+rename).  Lower values risk double-reloads
/// on slow disks; higher values make the reload feel sluggish.
const DEBOUNCE_MS: u64 = 500;

/// Channel capacity for the notify → Tokio bridge.
/// Capacity 1 is intentional: a second signal while one is already pending
/// is redundant (the pending signal already schedules a reload).  The send
/// uses `try_send` so the notify callback never blocks.
const SIGNAL_CHANNEL_CAPACITY: usize = 1;

// ── Public API ────────────────────────────────────────────────────────────────

pub struct PolicyWatcher {
    rules_path: PathBuf,
    reloader:   Arc<PolicyReloader>,
}

impl PolicyWatcher {
    /// Create a new watcher.
    ///
    /// `rules_path` must be the full path to `rules.yaml` — the same path
    /// passed to `PolicyReloader::new()`.
    pub fn new(rules_path: impl AsRef<Path>, reloader: Arc<PolicyReloader>) -> Self {
        Self {
            rules_path: rules_path.as_ref().to_path_buf(),
            reloader,
        }
    }

    /// Register the OS watch and spawn the debounce task.
    ///
    /// Returns `Err` only if the initial watch registration fails.
    /// After this call returns `Ok(())`, the watcher runs independently
    /// as a background Tokio task for the lifetime of the process.
    pub fn start(self) -> Result<()> {
        // ── Validate path ─────────────────────────────────────────────────
        //
        // Fail fast if rules.yaml doesn't exist — better than a silent
        // watcher that never fires because the path is wrong.
        if !self.rules_path.exists() {
            // Non-fatal: the file might be created later.  Warn but continue.
            warn!(
                path = %self.rules_path.display(),
                "rules.yaml does not exist yet — watcher registered but \
                 no events will fire until the file is created"
            );
        }

        // ── Channel: notify callback → Tokio debounce task ────────────────
        //
        // The channel carries a unit signal (no payload needed — any event
        // on the watched path means "reload").  Capacity 1 collapses bursts.
        let (tx, rx) = mpsc::channel::<()>(SIGNAL_CHANNEL_CAPACITY);

        // ── Notify watcher ────────────────────────────────────────────────
        //
        // `notify::recommended_watcher` selects the best OS primitive at
        // compile time: inotify on Linux, RDCW on Windows.
        //
        // The callback runs on a notify-internal thread (not Tokio).  It must
        // not block.  `tx.try_send(())` is non-blocking: if the channel is
        // already full the extra signal is silently dropped (debounce intent).
        let watch_path = self.rules_path.clone();

        let mut watcher: RecommendedWatcher = notify::recommended_watcher(
            move |result: notify::Result<notify::Event>| {
                match result {
                    Ok(event) => {
                        // Only react to events that modify file content.
                        // Ignore metadata-only changes (chmod, atime) and
                        // directory events that can fire when editors rename
                        // temp files into place.
                        let relevant = matches!(
                            event.kind,
                            EventKind::Modify(_)
                            | EventKind::Create(_)
                            | EventKind::Remove(_)
                        );

                        if relevant {
                            // Verify the event is for our specific file.
                            // The watcher is registered on the parent directory
                            // (see below) to catch atomic rename-based saves,
                            // so we must filter here.
                            let for_our_file = event.paths.iter().any(|p| p == &watch_path);

                            if for_our_file {
                                debug!(
                                    kind   = ?event.kind,
                                    path   = %watch_path.display(),
                                    "File-system event — signalling reload"
                                );
                                // try_send: non-blocking, drops if full (intentional).
                                let _ = tx.try_send(());
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "notify watcher error");
                    }
                }
            }
        ).context("Failed to create file-system watcher")?;

        // ── Watch the PARENT DIRECTORY, not the file directly ─────────────
        //
        // Why the parent dir?  Many editors (vim, nano, VSCode) save via an
        // atomic rename:
        //   1. Write to rules.yaml.tmp
        //   2. rename(rules.yaml.tmp, rules.yaml)
        //
        // inotify on Linux does NOT fire IN_MODIFY on the original inode
        // after a rename replaces it — the old inode is gone.  Watching the
        // parent directory catches the rename event on the directory entry
        // "rules.yaml", which is what we want.
        //
        // ReadDirectoryChangesW on Windows behaves similarly.
        //
        // RecursiveMode::NonRecursive: only watch the config directory
        // itself, not any subdirectories.
        let watch_dir = self.rules_path
            .parent()
            .context("rules.yaml path has no parent directory")?;

        watcher
            .watch(watch_dir, RecursiveMode::NonRecursive)
            .with_context(|| format!(
                "Failed to register filesystem watch on {}",
                watch_dir.display()
            ))?;

        info!(
            path      = %self.rules_path.display(),
            watch_dir = %watch_dir.display(),
            debounce_ms = DEBOUNCE_MS,
            "Policy hot-reload watcher active"
        );

        // ── Debounce task ─────────────────────────────────────────────────
        //
        // Runs as a detached Tokio task.  Holds the `_watcher` binding alive
        // so the OS watch remains registered for the process lifetime.
        let reloader   = self.reloader.clone();
        let rules_path = self.rules_path.clone();

        tokio::spawn(async move {
            // Keep the watcher alive inside the task.
            // Dropping it would deregister the OS watch.
            let _watcher = watcher;

            debounce_loop(rx, reloader, rules_path).await;
        });

        Ok(())
    }
}

// ── Debounce loop (runs inside the spawned task) ──────────────────────────────

async fn debounce_loop(
    mut rx:        mpsc::Receiver<()>,
    reloader:      Arc<PolicyReloader>,
    rules_path:    PathBuf,
) {
    loop {
        // Block until we receive the first signal for a burst.
        // If the channel is closed (sender dropped = watcher dropped),
        // the task exits cleanly.
        if rx.recv().await.is_none() {
            info!("Policy watcher channel closed — hot-reload task exiting");
            return;
        }

        // Drain any additional signals that arrived during the first
        // recv() await, then wait for DEBOUNCE_MS of silence.
        //
        // The loop: wait DEBOUNCE_MS; if a new signal arrives during the
        // wait, restart the timer.  Exit the inner loop only when the full
        // DEBOUNCE_MS elapses without another signal.
        loop {
            tokio::select! {
                biased; // poll `recv` first — prefer resetting over firing

                // A new signal arrived: reset the debounce timer.
                signal = rx.recv() => {
                    if signal.is_none() {
                        info!("Policy watcher channel closed — hot-reload task exiting");
                        return;
                    }
                    debug!("Debounce reset — another write event received");
                    // Loop again: start a fresh DEBOUNCE_MS wait.
                }

                // Silence for DEBOUNCE_MS: fire the reload.
                _ = sleep(Duration::from_millis(DEBOUNCE_MS)) => {
                    break; // exit inner loop → trigger reload below
                }
            }
        }

        // ── Reload ────────────────────────────────────────────────────────
        info!(
            path = %rules_path.display(),
            "Detected change in rules.yaml — reloading policy rules"
        );

        match reloader.reload() {
            Ok(()) => info!(
                path = %rules_path.display(),
                "Policy rules reloaded successfully"
            ),
            Err(e) => warn!(
                path  = %rules_path.display(),
                error = %e,
                "Policy reload failed — previous rule set remains active"
            ),
        }
    }
}
