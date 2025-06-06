//! Common code for the noble-migration that is used by check and upgrade
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::Path,
    process::{self},
};
use url::{Host, Url};
use walkdir::WalkDir;

#[derive(Serialize)]
pub struct State {
    ssh: bool,
    ufw: bool,
    free_space: bool,
    apt: bool,
    systemd: bool,
    ethernet: bool,
}

impl State {
    pub fn is_ready(&self) -> bool {
        self.is_ready_except_apt() && self.apt
    }

    /// For when developers inject extra APT sources for testing
    pub fn is_ready_except_apt(&self) -> bool {
        self.ssh && self.ufw && self.free_space && self.systemd && self.ethernet
    }
}

/// Parse the OS codename from /etc/os-release
pub fn os_codename() -> Result<String> {
    let contents = fs::read_to_string("/etc/os-release")
        .context("reading /etc/os-release failed")?;
    for line in contents.lines() {
        if line.starts_with("VERSION_CODENAME=") {
            // unwrap: Safe because we know the line contains "="
            let (_, codename) = line.split_once("=").unwrap();
            return Ok(codename.trim().to_string());
        }
    }

    bail!("Could not find VERSION_CODENAME in /etc/os-release")
}

/// Check that the UNIX "ssh" group has no members
///
/// See <https://github.com/freedomofpress/securedrop/issues/7316>.
fn check_ssh_group() -> Result<bool> {
    // There are no clean bindings to getgrpname in rustix,
    // so just shell out to getent to get group members
    let output = process::Command::new("getent")
        .arg("group")
        .arg("ssh")
        .output()
        .context("spawning getent failed")?;
    if output.status.code() == Some(2) {
        println!("ssh OK: group does not exist");
        return Ok(true);
    } else if !output.status.success() {
        bail!(
            "running getent failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8(output.stdout)
        .context("getent stdout is not utf-8")?;
    let members = parse_getent_output(&stdout)?;
    if members.is_empty() {
        println!("ssh OK: group is empty");
        Ok(true)
    } else {
        println!("ssh ERROR: group is not empty: {members:?}");
        Ok(false)
    }
}

/// Parse the output of `getent group ssh`, return true if empty
fn parse_getent_output(stdout: &str) -> Result<Vec<&str>> {
    let stdout = stdout.trim();
    // The format looks like `ssh:x:123:member1,member2`
    if !stdout.contains(":") {
        bail!("unexpected output from getent: '{stdout}'");
    }

    // unwrap: safe, we know the line contains ":"
    let (_, members) = stdout.rsplit_once(':').unwrap();
    if members.is_empty() {
        Ok(vec![])
    } else {
        Ok(members.split(',').collect())
    }
}

/// Check that ufw was removed
///
/// See <https://github.com/freedomofpress/securedrop/issues/7313>.
fn check_ufw_removed() -> bool {
    if Path::new("/usr/sbin/ufw").exists() {
        println!("ufw ERROR: ufw is still installed");
        false
    } else {
        println!("ufw OK: ufw was removed");
        true
    }
}

/// Estimate the size of the backup so we know how much free space we'll need.
///
/// We just check the size of `/var/lib/securedrop` since that's really the
/// data that'll take up space; everything else is just config files that are
/// negligible post-compression. We also don't estimate compression benefits.
fn estimate_backup_size() -> Result<u64> {
    let path = Path::new("/var/lib/securedrop");
    if !path.exists() {
        // mon server
        return Ok(0);
    }
    let mut total: u64 = 0;
    let walker = WalkDir::new(path);
    for entry in walker {
        let entry = entry.context("walking /var/lib/securedrop failed")?;
        if entry.file_type().is_dir() {
            continue;
        }
        let metadata = entry.metadata().context("getting metadata failed")?;
        total += metadata.len();
    }

    Ok(total)
}

/// We want to have enough space for a backup, the upgrade (~4GB of packages,
/// conservatively), and not take up more than 90% of the disk.
fn check_free_space() -> Result<bool> {
    // Also no simple bindings to get disk size, so shell out to df
    // Explicitly specify -B1 for bytes (not kilobytes)
    let output = process::Command::new("df")
        .args(["-B1", "/"])
        .output()
        .context("spawning df failed")?;
    if !output.status.success() {
        bail!(
            "running df failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout =
        String::from_utf8(output.stdout).context("df stdout is not utf-8")?;
    let parsed = parse_df_output(&stdout)?;

    let backup_needs = estimate_backup_size()?;
    let upgrade_needs: u64 = 4 * 1024 * 1024 * 1024; // 4GB
    let headroom = parsed.total / 10; // 10% headroom
    let total_needs = backup_needs + upgrade_needs + headroom;

    if parsed.free < total_needs {
        println!(
            "free space ERROR: not enough free space, have {} free bytes, need {total_needs} bytes",
            parsed.free
        );
        Ok(false)
    } else {
        println!("free space OK: enough free space");
        Ok(true)
    }
}

/// Sizes are in bytes
struct DfOutput {
    total: u64,
    free: u64,
}

fn parse_df_output(stdout: &str) -> Result<DfOutput> {
    let line = match stdout.split_once('\n') {
        Some((_, line)) => line,
        None => bail!("df output didn't have a newline"),
    };
    let parts: Vec<_> = line.split_whitespace().collect();

    if parts.len() < 4 {
        bail!("df output didn't have enough columns");
    }

    // vec indexing is safe because we did the bounds check above
    let total = parts[1]
        .parse::<u64>()
        .context("parsing total space failed")?;
    let free = parts[3]
        .parse::<u64>()
        .context("parsing free space failed")?;

    Ok(DfOutput { total, free })
}

const EXPECTED_DOMAINS: [&str; 3] = [
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "apt.freedom.press",
];

const TEST_DOMAINS: [&str; 2] =
    ["apt-qa.freedom.press", "apt-test.freedom.press"];

/// Verify only expected sources are configured for apt
fn check_apt() -> Result<bool> {
    let output = process::Command::new("apt-get")
        .arg("indextargets")
        .output()
        .context("spawning apt-get indextargets failed")?;
    if !output.status.success() {
        bail!(
            "running apt-get indextargets failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8(output.stdout)
        .context("apt-get stdout is not utf-8")?;
    for line in stdout.lines() {
        if line.starts_with("URI:") {
            let uri = line.strip_prefix("URI: ").unwrap();
            let parsed = Url::parse(uri)?;
            if let Some(Host::Domain(domain)) = parsed.host() {
                if TEST_DOMAINS.contains(&domain) {
                    println!("apt: WARNING test source found ({domain})");
                } else if !EXPECTED_DOMAINS.contains(&domain) {
                    println!("apt ERROR: unexpected source: {domain}");
                    return Ok(false);
                }
            } else {
                println!("apt ERROR: unexpected source: {uri}");
                return Ok(false);
            }
        }
    }

    println!("apt OK: all sources are expected");
    Ok(true)
}

/// Check that systemd has no failed units
pub fn check_systemd() -> Result<bool> {
    let output = process::Command::new("systemctl")
        .arg("is-failed")
        .output()
        .context("spawning systemctl failed")?;
    if output.status.success() {
        // success means some units are failed
        println!("systemd ERROR: some units are failed");
        Ok(false)
    } else {
        println!("systemd OK: all units are happy");
        Ok(true)
    }
}

#[derive(Deserialize)]
struct IpInterface {
    ifname: String,
    operstate: String,
}

fn check_ethernet() -> Result<bool> {
    let output = process::Command::new("ip")
        .args(["-json", "-brief", "addr", "show"])
        .output()?;
    if !output.status.success() {
        bail!(
            "invoking ip failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    parse_ip_output(&output.stdout)
}

fn parse_ip_output(stdout: &[u8]) -> Result<bool> {
    let interfaces: Vec<IpInterface> = serde_json::from_slice(stdout)?;
    let mut down = vec![];
    for interface in interfaces {
        if interface.ifname == "lo" {
            // skip loopback
            continue;
        }
        if interface.operstate != "UP" {
            down.push(interface.ifname);
        }
    }
    if !down.is_empty() {
        println!("ethernet ERROR: interfaces are down: {down:?}");
        return Ok(false);
    }
    println!("ethernet OK: all interfaces are up");
    Ok(true)
}

pub fn run_checks() -> Result<State> {
    Ok(State {
        ssh: check_ssh_group()?,
        ufw: check_ufw_removed(),
        free_space: check_free_space()?,
        apt: check_apt()?,
        systemd: check_systemd()?,
        ethernet: check_ethernet()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_getent_output() {
        // no members
        assert_eq!(
            parse_getent_output("ssh:x:123:\n").unwrap(),
            Vec::<&str>::new()
        );
        // one member
        assert_eq!(
            parse_getent_output("ssh:x:123:member1\n").unwrap(),
            vec!["member1"]
        );
        // two members
        assert_eq!(
            parse_getent_output("ssh:x:123:member1,member2\n").unwrap(),
            vec!["member1", "member2"]
        );
    }

    #[test]
    fn test_parse_df_output() {
        let output = parse_df_output(
            "Filesystem                           1B-blocks       Used   Available Use% Mounted on
/dev/mapper/ubuntu--vg-ubuntu--lv 105089261568 8573784064 91129991168   9% /
",
        )
        .unwrap();

        assert_eq!(output.total, 105089261568);
        assert_eq!(output.free, 91129991168);
    }

    #[test]
    fn test_parse_netplan_output() {
        // one interface that's UP (prod) -> true
        let input = br#"[{"ifname":"lo","operstate":"UNKNOWN","addr_info":[{"local":"127.0.0.1","prefixlen":8}]},{"ifname":"enp89s0","operstate":"UP","addr_info":[{"local":"10.20.2.2","prefixlen":24}]}]"#;
        let output = parse_ip_output(input).unwrap();
        assert!(output);
        // one UP and one DOWN -> false
        let input2 = br#"[{"ifname":"lo","operstate":"UNKNOWN","addr_info":[{"local":"127.0.0.1","prefixlen":8}]},{"ifname":"eth0","operstate":"DOWN", "addr_info":[]},{"ifname":"eth1","operstate":"UP","addr_info":[{"local":"10.0.1.3","prefixlen":24}]}]"#;
        let output2 = parse_ip_output(input2).unwrap();
        assert!(!output2);
        // two UP interfaces (staging) -> true
        let input3 = br#"[{"ifname":"lo","operstate":"UNKNOWN","addr_info":[{"local":"127.0.0.1","prefixlen":8}]},{"ifname":"eth0","operstate":"UP","addr_info":[{"local":"192.168.121.247","prefixlen":24,"metric":100}]},{"ifname":"eth1","operstate":"UP","addr_info":[{"local":"10.0.1.3","prefixlen":24}]}]"#;
        let output3 = parse_ip_output(input3).unwrap();
        assert!(output3);
    }
}
