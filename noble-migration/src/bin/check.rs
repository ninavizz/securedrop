//! Check migration of a SecureDrop server from focal to noble
//!
//! This script is run as root on both the app and mon servers.
//!
//! It is typically run by a systemd service/timer, but we also
//! support admins running it manually to get more detailed output.
use anyhow::{Context, Result};
use rustix::process::geteuid;
use std::{fs, process::ExitCode};

/// This file contains the state of the pre-migration checks.
///
/// There are four possible states:
/// * does not exist: check script hasn't run yet
/// * empty JSON object: script determines it isn't on focal
/// * {"error": true}: script encountered an error
/// * JSON object with boolean values for each check (see `State` struct)
const STATE_PATH: &str = "/etc/securedrop-noble-migration.json";

fn run() -> Result<()> {
    let codename = noble_migration::os_codename()?;
    if codename != "focal" {
        println!("Unsupported Ubuntu version: {codename}");
        // nothing to do, write an empty JSON blob
        fs::write(STATE_PATH, "{}")?;
        return Ok(());
    }

    let state = noble_migration::run_checks()?;

    fs::write(
        STATE_PATH,
        serde_json::to_string(&state).context("serializing state failed")?,
    )
    .context("writing state file failed")?;
    if state.is_ready() {
        println!("All ready for migration!");
    } else {
        println!();
        println!(
            "Some errors were found that will block migration.

Documentation on how to resolve these errors can be found at:
<https://docs.securedrop.org/en/stable/admin/maintenance/noble_migration_prep.html>

If you are unsure what to do, please contact the SecureDrop
support team: <https://docs.securedrop.org/en/stable/getting_support.html>."
        );
        // Logically we should exit with a failure here, but we don't
        // want the systemd unit to fail.
    }
    Ok(())
}

fn main() -> Result<ExitCode> {
    if !geteuid().is_root() {
        println!("This script must be run as root");
        return Ok(ExitCode::FAILURE);
    }

    match run() {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(e) => {
            // Try to log the error in the least complex way possible
            fs::write(STATE_PATH, "{\"error\": true}")?;
            eprintln!("Error running migration pre-check: {e}");
            Ok(ExitCode::FAILURE)
        }
    }
}
