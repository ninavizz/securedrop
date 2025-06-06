//! Migrate a SecureDrop server from focal to noble
//!
//! This script must never be run directly, only via the
//! systemd service, which is enforced by checking $LAUNCHED_BY_SYSTEMD in main() below.
use anyhow::{bail, Context, Result};
use log::{debug, error, info};
use rand::{thread_rng, Rng};
use rustix::process::geteuid;
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::{self, Permissions},
    os::unix::{
        fs::PermissionsExt,
        process::{CommandExt, ExitStatusExt},
    },
    path::Path,
    process::{self, Command, ExitCode},
};

/// Configuration for the migration process (installed by securedrop-config)
const CONFIG_PATH: &str = "/usr/share/securedrop/noble-upgrade.json";
/// Serialized version of `State` (left by the last run of this script)
const STATE_PATH: &str = "/etc/securedrop-noble-migration-state.json";
const MON_OSSEC_CONFIG: &str = "/var/ossec/etc/ossec.conf";
/// Environment variable to allow developers to inject an extra APT source
const EXTRA_APT_SOURCE: &str = "EXTRA_APT_SOURCE";

/// All the different steps in the migration
///
/// Each stage needs to be idempotent so that it can be run multiple times
/// in case it errors/crashes.
///
/// Keep this in sync with the version in noble-migration/tasks/main.yml
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
enum Stage {
    None,
    MigrationCheck,
    PendingUpdates,
    DisableApache2,
    Backup,
    BackupIptables,
    Marker,
    SuspendOSSEC,
    ChangeAptSources,
    AptGetUpdate,
    AptGetFullUpgrade,
    AptGetAutoremove,
    RestoreIptables,
    ReenableUnattendedUpdates,
    ReenableOSSEC,
    Reboot,
    SwitchUbuntuSources,
    IntegrityCheck,
    ReenableApache2,
    RemoveBackup,
    Done,
}

/// Current state of the migration.
#[derive(Serialize, Deserialize, Debug)]
struct State {
    /// most recently finished stage. This is updated
    /// on-disk as soon as every stage is completed.
    finished: Stage,
    /// randomly selected number between 1 and 5, which is used
    /// to auto-migrate instances in batches. This number is generated once,
    /// when the service is first run.
    bucket: usize,
}

impl State {
    /// Load the State file from disk, or create it if it doesn't exist
    ///
    /// This is run on every invocation of the script, even if auto-migration
    /// isn't enabled yet. This allows the bucket to be generated only once.
    fn load() -> Result<Self> {
        if !Path::new(STATE_PATH).exists() {
            debug!("State file, {}, doesn't exist; state=None", STATE_PATH);
            let mut rng = thread_rng();
            let state = State {
                finished: Stage::None,
                bucket: rng.gen_range(1..=5),
            };
            // Persist the randomly selected bucket
            state.save()?;
            return Ok(state);
        }
        debug!("Loading state from {}", STATE_PATH);
        // If this fails we're basically stuck.
        let state = serde_json::from_str(
            &fs::read_to_string(STATE_PATH)
                .context("Unable to read STATE_PATH")?,
        )
        .context("Deserializing STATE_PATH failed")?;
        debug!("Loaded state: {state:?}");
        Ok(state)
    }

    /// Set the specified stage as finished and persist to disk
    fn set(&mut self, stage: Stage) -> Result<()> {
        debug!("Finished stage {stage:?}");
        self.finished = stage;
        self.save()
    }

    /// Persist current state to disk
    fn save(&self) -> Result<()> {
        fs::write(
            STATE_PATH,
            serde_json::to_string(self).context("Failed to serialize state")?,
        )
        .context("Failed to write state")
    }
}

/// State machine to invoke the next stage based on what has finished.
fn run_next_stage(state: &mut State) -> Result<()> {
    match state.finished {
        Stage::None => {
            migration_check()?;
            state.set(Stage::MigrationCheck)?;
        }
        Stage::MigrationCheck => {
            pending_updates(state)?;
            unreachable!("script should have already exited/rebooted");
        }
        Stage::PendingUpdates => {
            disable_apache2()?;
            state.set(Stage::DisableApache2)?;
        }
        Stage::DisableApache2 => {
            backup()?;
            state.set(Stage::Backup)?;
        }
        Stage::Backup => {
            backup_iptables()?;
            state.set(Stage::BackupIptables)?;
        }
        Stage::BackupIptables => {
            marker()?;
            state.set(Stage::Marker)?;
        }
        Stage::Marker => {
            suspend_ossec()?;
            state.set(Stage::SuspendOSSEC)?;
        }
        Stage::SuspendOSSEC => {
            change_apt_sources()?;
            state.set(Stage::ChangeAptSources)?;
        }
        Stage::ChangeAptSources => {
            apt_get_update()?;
            state.set(Stage::AptGetUpdate)?;
        }
        Stage::AptGetUpdate => {
            apt_get_full_upgrade()?;
            state.set(Stage::AptGetFullUpgrade)?;
        }
        Stage::AptGetFullUpgrade => {
            apt_get_autoremove()?;
            state.set(Stage::AptGetAutoremove)?;
        }
        Stage::AptGetAutoremove => {
            restore_iptables()?;
            state.set(Stage::RestoreIptables)?;
        }
        Stage::RestoreIptables => {
            reenable_unattended_updates()?;
            state.set(Stage::ReenableUnattendedUpdates)?;
        }
        Stage::ReenableUnattendedUpdates => {
            reenable_ossec()?;
            state.set(Stage::ReenableOSSEC)?;
        }
        Stage::ReenableOSSEC => {
            reboot(state)?;
            unreachable!("script should have already exited/rebooted");
        }
        Stage::Reboot => {
            switch_ubuntu_sources()?;
            state.set(Stage::SwitchUbuntuSources)?;
        }
        Stage::SwitchUbuntuSources => {
            integrity_check()?;
            state.set(Stage::IntegrityCheck)?;
        }
        Stage::IntegrityCheck => {
            reenable_apache2()?;
            state.set(Stage::ReenableApache2)?;
        }
        Stage::ReenableApache2 => {
            remove_backup()?;
            state.set(Stage::RemoveBackup)?;
        }
        Stage::RemoveBackup => {
            state.set(Stage::Done)?;
        }
        Stage::Done => {}
    }
    Ok(())
}

/// A wrapper to roughly implement Python's subprocess.check_call/check_output
fn check_call(binary: &str, args: &[&str]) -> Result<String> {
    debug!("Running: {binary} {}", args.join(" "));
    let output = Command::new(binary)
        .args(args)
        // Always set apt's non-interactive mode
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output()
        .context(format!("failed to spawn/execute '{binary}'"))?;
    if output.status.success() {
        debug!("Finished running: {binary} {}", args.join(" "));
        // In theory we could use from_utf8_lossy here as we're not expecting
        // any non-UTF-8 output, but let's error in that case.
        let stdout = String::from_utf8(output.stdout)
            .context("stdout contains non-utf8 bytes")?;
        debug!("{stdout}");
        Ok(stdout)
    } else {
        debug!("Errored running: {binary} {}", args.join(" "));
        // Figure out why it failed by looking at the exit code, and if none,
        // look at if it was a signal
        let exit = match output.status.code() {
            Some(code) => format!("exit code {code}"),
            None => match output.status.signal() {
                Some(signal) => format!("terminated by signal {signal}"),
                None => "for an unknown reason".to_string(),
            },
        };
        error!("{}", String::from_utf8_lossy(&output.stderr));
        bail!("running '{binary}' failed; {exit}")
    }
}

/// Roughly the same as `check_call`, but run the command in a way that it
/// will keep running even when this script is killed. This is necessary
/// to keep apt-get from getting killed when the systemd service is restarted.
fn check_call_nokill(binary: &str, args: &[&str]) -> Result<()> {
    let child = Command::new(binary)
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        // Run this in a separate process_group, so it won't be killed when
        // the parent process is (this script).
        .process_group(0)
        // Let stdout/stderr to the parent; journald will pick it up
        .spawn()
        .context(format!("failed to spawn '{binary}'"))?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        debug!("Errored running: {binary} {}", args.join(" "));
        // Figure out why it failed by looking at the exit code, and if none,
        // look at if it was a signal
        let exit = match output.status.code() {
            Some(code) => format!("exit code {code}"),
            None => match output.status.signal() {
                Some(signal) => format!("terminated by signal {signal}"),
                None => "for an unknown reason".to_string(),
            },
        };
        error!("{}", String::from_utf8_lossy(&output.stderr));
        bail!("running '{binary}' failed; {exit}")
    }

    Ok(())
}

/// Check if the current server is the mon server by
/// looking for the securedrop-ossec-server package
fn is_mon_server() -> bool {
    Path::new("/usr/share/doc/securedrop-ossec-server/copyright").exists()
}

/// Step 1: Run the migration check
///
/// Run the same migration check as a final verification step before
/// we begin
fn migration_check() -> Result<()> {
    info!("Checking pre-migration steps...");
    // This should've been caught in should_upgrade() but let's double check
    if noble_migration::os_codename()? != "focal" {
        bail!("not a focal system");
    }
    let state =
        noble_migration::run_checks().context("migration check errored")?;

    if env::var(EXTRA_APT_SOURCE).is_ok() {
        // If we're injecting an extra APT source, then allow that check to fail
        if !state.is_ready_except_apt() {
            bail!("Migration check failed")
        }
    } else if !state.is_ready() {
        bail!("Migration check failed")
    }

    Ok(())
}

/// Step 2: Apply any pending updates
///
/// Explicitly run unattended-upgrade, then disable it and reboot
fn pending_updates(state: &mut State) -> Result<()> {
    info!("Applying any pending updates...");
    check_call("apt-get", &["update"])?;
    check_call_nokill("unattended-upgrade", &[])?;
    // Disable all background updates pre-reboot so we know it's fully
    // disabled when we come back.
    info!("Temporarily disabling background updates...");
    check_call("systemctl", &["mask", "unattended-upgrades"])?;
    check_call("systemctl", &["mask", "apt-daily"])?;
    check_call("systemctl", &["mask", "apt-daily-upgrade"])?;
    state.set(Stage::PendingUpdates)?;
    check_call("systemctl", &["reboot"])?;
    // Because we've initiated the reboot, do a hard stop here to ensure that
    // we don't keep moving forward if the reboot doesn't happen instantly
    process::exit(0);
}

/// Step 3: Disable apache2
///
/// On the app server, disable apache for the duration of the upgrade to prevent
/// any modifications to the SecureDrop database/state
fn disable_apache2() -> Result<()> {
    if is_mon_server() {
        return Ok(());
    }
    info!("Stopping web server for duration of upgrade...");
    check_call("systemctl", &["mask", "apache2"])?;
    Ok(())
}

/// Step 4: Take a backup
///
/// On the app server, run the normal backup script for disaster recovery
/// in case something does go wrong
fn backup() -> Result<()> {
    if is_mon_server() {
        return Ok(());
    }
    info!("Taking a backup...");
    // Create a root-only directory to store the backup
    if !Path::new("/var/lib/securedrop-backups").exists() {
        fs::create_dir("/var/lib/securedrop-backups")?
    }
    let permissions = Permissions::from_mode(0o700);
    fs::set_permissions("/var/lib/securedrop-backups", permissions)?;
    check_call(
        "/usr/bin/securedrop-app-backup.py",
        &["--dest", "/var/lib/securedrop-backups"],
    )?;
    Ok(())
}

/// Step 5: Backup the iptables rules
///
/// During the iptables-persistent upgrade, the iptables rules get wiped. Because
/// these are generated by ansible, back up them up ahead of time and then we'll
/// restore them after the upgrade. We don't delete them post-upgrade just in case
/// something goes wrong to make it easy to restore.
fn backup_iptables() -> Result<()> {
    info!("Backing up iptables...");
    if !Path::new("/etc/securedrop-backup").exists() {
        fs::create_dir("/etc/securedrop-backup")?;
    }
    fs::copy(
        "/etc/iptables/rules.v4",
        "/etc/securedrop-backup/iptables-rules.v4",
    )?;
    fs::copy(
        "/etc/iptables/rules.v6",
        "/etc/securedrop-backup/iptables-rules.v6",
    )?;
    Ok(())
}

/// Step 6: Write an upgrade marker file
///
/// Write a marker file to indicate that we've upgraded from focal. There is no
/// use for this file right now, but if we discover some sort of variance in the
/// future, we can look for the existence of this file to conditionally guard
/// actions based on it.
fn marker() -> Result<()> {
    info!("Writing upgrade marker file...");
    fs::write("/etc/securedrop-upgraded-from-focal", "yes")
        .context("failed to write upgrade marker file")
}

/// Step 7: Suspend OSSEC notifications
///
/// On the mon server, raise the OSSEC alert level to prevent a bajillion
/// notifications from being sent.
fn suspend_ossec() -> Result<()> {
    if !is_mon_server() {
        return Ok(());
    }
    info!("Temporarily suspending most OSSEC notifications...");
    let current = fs::read_to_string(MON_OSSEC_CONFIG)?;
    let new = current.replace(
        "<email_alert_level>7</email_alert_level>",
        "<email_alert_level>15</email_alert_level>",
    );
    fs::write(MON_OSSEC_CONFIG, new)?;
    check_call("systemctl", &["restart", "ossec"])?;
    Ok(())
}

/// Step 8: Switch APT sources
///
/// Update all the APT sources to use noble. Developers can set
/// EXTRA_APT_SOURCE in the systemd unit to inject an extra APT source
/// (e.g. apt-qa).
fn change_apt_sources() -> Result<()> {
    info!("Switching APT sources to noble...");
    fs::write(
        "/etc/apt/sources.list",
        include_str!("../../files/sources.list"),
    )?;
    let mut contents =
        include_str!("../../files/apt_freedom_press.list").to_string();
    // Allow developers to inject an extra APT source
    if let Ok(extra) = env::var(EXTRA_APT_SOURCE) {
        contents.push_str(format!("\n{extra}\n").as_str());
    }
    fs::write("/etc/apt/sources.list.d/apt_freedom_press.list", contents)?;
    Ok(())
}

/// Step 9: Update APT cache
///
/// Standard apt-get update
fn apt_get_update() -> Result<()> {
    info!("Updating APT cache...");
    check_call("apt-get", &["update"])?;
    Ok(())
}

/// Step 10: Upgrade APT packages
///
/// Actually do the upgrade! We pass --force-confold to tell dpkg
/// to always keep the old config files if they've been modified (by us).
///
/// We use the nokill invocation because otherwise when the securedrop-config
/// package is upgraded, it'll kill this script and apt-get. In case we are killed,
/// apt-get will keep going. We'll rely on apt/dpkg's locking mechanism to prevent
/// duplicate processes.
///
/// This command is idempotent since running it after the upgrade is done will just
/// upgrade no packages.
///
/// Theoretically once this step finishes, we're on a noble system.
fn apt_get_full_upgrade() -> Result<()> {
    info!("Upgrading APT packages...");
    check_call_nokill(
        "apt-get",
        &[
            "-o",
            "Dpkg::Options::=--force-confold",
            "full-upgrade",
            "--yes",
        ],
    )?;
    Ok(())
}

/// Step 11: Remove removable APT packages
///
/// Standard apt-get autoremove.
fn apt_get_autoremove() -> Result<()> {
    info!("Removing removable APT packages...");
    check_call_nokill("apt-get", &["autoremove", "--yes"])?;
    Ok(())
}

/// Step 12: Restore iptables rules
///
/// Now that we've upgraded, move the backups of the iptables rules we created
/// into place and clean up the backups.
fn restore_iptables() -> Result<()> {
    info!("Restoring iptables...");
    fs::copy(
        "/etc/securedrop-backup/iptables-rules.v4",
        "/etc/iptables/rules.v4",
    )?;
    fs::copy(
        "/etc/securedrop-backup/iptables-rules.v6",
        "/etc/iptables/rules.v6",
    )?;
    Ok(())
}

/// Step 13: Re-enable unattended-updates
///
/// Re-enable all the unattended-upgrades units we disabled earlier.
fn reenable_unattended_updates() -> Result<()> {
    info!("Re-enabling background updates...");
    check_call("systemctl", &["unmask", "unattended-upgrades"])?;
    check_call("systemctl", &["unmask", "apt-daily"])?;
    check_call("systemctl", &["unmask", "apt-daily-upgrade"])?;
    Ok(())
}

/// Step 14: Re-enable OSSEC notifications
///
/// Undo our suspending of OSSEC notifications.
fn reenable_ossec() -> Result<()> {
    if !is_mon_server() {
        return Ok(());
    }
    info!("Re-enabling OSSEC notifications...");
    let current = fs::read_to_string(MON_OSSEC_CONFIG)?;
    let new = current.replace(
        "<email_alert_level>15</email_alert_level>",
        "<email_alert_level>7</email_alert_level>",
    );
    fs::write(MON_OSSEC_CONFIG, new)?;
    check_call("systemctl", &["restart", "ossec"])?;
    Ok(())
}

/// Step 15: Reboot
///
/// Reboot!
fn reboot(state: &mut State) -> Result<()> {
    info!("Rebooting!");
    state.set(Stage::Reboot)?;
    check_call("systemctl", &["reboot"])?;
    // Because we've initiated the reboot, do a hard stop here to ensure that
    // we don't keep moving forward if the reboot doesn't happen instantly
    process::exit(0);
}

/// Step 16: Switch APT sources format
///
/// Switch to the new APT deb822 sources format for ubuntu.sources
/// to mirror how the noble installer generates it.
///
/// We cannot do this earlier because focal's apt doesn't understand it.
fn switch_ubuntu_sources() -> Result<()> {
    info!("Switching APT sources format...");
    fs::write(
        "/etc/apt/sources.list.d/ubuntu.sources",
        include_str!("../../files/ubuntu.sources"),
    )
    .context("failed to write ubuntu.sources")?;
    fs::remove_file("/etc/apt/sources.list")
        .context("failed to remove sources.list")?;
    // Verify APT is happy with the new file
    check_call("apt-get", &["update"])?;
    Ok(())
}

/// Step 17: Integrity check
///
/// Before we turn the system back on, check that nothing is obviously wrong
fn integrity_check() -> Result<()> {
    info!("Running integrity check post-upgrade...");
    // Check systemd units are happy
    if !noble_migration::check_systemd()? {
        bail!("some systemd units are not happy");
    }
    // Very simple check that the iptables firewall is up
    let iptables = check_call("iptables", &["-S"])?;
    if !iptables.contains("INPUT DROP") {
        bail!("iptables firewall is not up");
    }
    Ok(())
}

/// Step 18: Re-enable Apache
///
/// Fire up app's web server now that we're done
fn reenable_apache2() -> Result<()> {
    if is_mon_server() {
        return Ok(());
    }
    info!("Starting web server...");
    check_call("systemctl", &["unmask", "apache2"])?;
    check_call("systemctl", &["start", "apache2"])?;
    Ok(())
}

/// Step 19: Remove backup
///
/// Now that we've finished, remove the backup we created earlier.
fn remove_backup() -> Result<()> {
    if is_mon_server() {
        return Ok(());
    }
    info!("Deleting backup...");
    fs::remove_dir_all("/var/lib/securedrop-backups")?;
    Ok(())
}

#[derive(Deserialize)]
struct UpgradeConfig {
    app: HostUpgradeConfig,
    mon: HostUpgradeConfig,
}

#[derive(Deserialize)]
struct HostUpgradeConfig {
    /// whether upgrades are enabled
    enabled: bool,
    /// The `bucket` setting increases inclusively: i.e., `bucket=1` enables hosts in bucket 1 to upgrade; `bucket=2` enables hosts in buckets 1 and 2 to upgrade; etc.
    bucket: usize,
}

fn should_upgrade(state: &State) -> Result<bool> {
    let config: UpgradeConfig = serde_json::from_str(
        &fs::read_to_string(CONFIG_PATH)
            .context("failed to read CONFIG_PATH")?,
    )
    .context("failed to deserialize CONFIG_PATH")?;
    // If we've already started the upgrade, keep going regardless of config
    if state.finished != Stage::None {
        info!("Upgrade has already started; will keep going");
        return Ok(true);
    }
    // Check if we're already on a noble system and we're not mid-upgrade
    if state.finished == Stage::None
        && noble_migration::os_codename()? == "noble"
    {
        info!("Already on a noble system; no need to upgrade.");
        return Ok(false);
    }
    let (for_host, host_name) = if is_mon_server() {
        (&config.mon, "mon")
    } else {
        (&config.app, "app")
    };
    if !for_host.enabled {
        info!("Auto-upgrades are disabled ({host_name})");
        return Ok(false);
    }
    if for_host.bucket < state.bucket {
        info!(
            "Auto-upgrades are enabled ({host_name}), but our bucket hasn't been enabled yet"
        );
        return Ok(false);
    }

    Ok(true)
}

fn main() -> Result<ExitCode> {
    env_logger::init();

    if !geteuid().is_root() {
        error!("This script must be run as root");
        return Ok(ExitCode::FAILURE);
    }

    if env::var("LAUNCHED_BY_SYSTEMD").is_err() {
        error!("This script must be run from the systemd unit");
        return Ok(ExitCode::FAILURE);
    }

    let mut state = State::load()?;
    if !should_upgrade(&state)? {
        return Ok(ExitCode::SUCCESS);
    }
    info!("Starting migration from state: {:?}", state.finished);
    loop {
        run_next_stage(&mut state)?;
        if state.finished == Stage::Done {
            break;
        }
    }

    Ok(ExitCode::SUCCESS)
}
