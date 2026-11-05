//! Service manager notifications. Under systemd (Linux, `systemd` feature)
//! they go to sd_notify; everywhere else they are no-ops, so the crate
//! builds on FreeBSD without libsystemd.

#[cfg(all(target_os = "linux", feature = "systemd"))]
pub fn ready() {
    if let Err(e) = systemd::daemon::notify(false, [(systemd::daemon::STATE_READY, "1")].iter()) {
        tracing::warn!("sd_notify ready: {e}");
    }
}

#[cfg(all(target_os = "linux", feature = "systemd"))]
pub fn watchdog() {
    if let Err(e) = systemd::daemon::notify(false, [(systemd::daemon::STATE_WATCHDOG, "1")].iter()) {
        tracing::warn!("sd_notify watchdog: {e}");
    }
}

#[cfg(not(all(target_os = "linux", feature = "systemd")))]
pub fn ready() {}

#[cfg(not(all(target_os = "linux", feature = "systemd")))]
pub fn watchdog() {}
