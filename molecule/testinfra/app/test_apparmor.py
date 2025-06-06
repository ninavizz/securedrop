import pytest
import testutils

sdvars = testutils.securedrop_test_vars
testinfra_hosts = [sdvars.app_hostname]


@pytest.mark.parametrize("pkg", ["apparmor", "apparmor-utils"])
def test_apparmor_pkg(host, pkg):
    """Apparmor package dependencies"""
    assert host.package(pkg).is_installed


def test_apparmor_enabled(host):
    """Check that apparmor is enabled"""
    with host.sudo():
        assert host.run("aa-status --enabled").rc == 0


apache2_capabilities = ["dac_override", "kill", "net_bind_service", "sys_ptrace"]


@pytest.mark.parametrize("cap", apache2_capabilities)
def test_apparmor_apache_capabilities(host, cap):
    """check for exact list of expected app-armor capabilities for apache2"""
    c = host.run(
        r"perl -nE '/^\s+capability\s+(\w+),$/ && say $1' /etc/apparmor.d/usr.sbin.apache2"
    )
    assert cap in c.stdout


def test_apparmor_apache_exact_capabilities(host):
    """ensure no extra capabilities are defined for apache2"""
    c = host.check_output("grep -ic capability /etc/apparmor.d/usr.sbin.apache2")
    assert str(len(apache2_capabilities)) == c


tor_capabilities = ["setgid"]


@pytest.mark.parametrize("cap", tor_capabilities)
def test_apparmor_tor_capabilities(host, cap):
    """check for exact list of expected app-armor capabilities for Tor"""
    c = host.run(r"perl -nE '/^\s+capability\s+(\w+),$/ && say $1' /etc/apparmor.d/usr.sbin.tor")
    assert cap in c.stdout


def test_apparmor_tor_exact_capabilities(host):
    """ensure no extra capabilities are defined for Tor"""
    c = host.check_output("grep -ic capability " "/etc/apparmor.d/usr.sbin.tor")
    assert str(len(tor_capabilities)) == c


def test_apparmor_ensure_not_disabled(host):
    """
    Explicitly check that there are no profiles in /etc/apparmor.d/disabled
    """
    with host.sudo():
        # Check that there are no apparmor profiles disabled because the folder is missing
        folder = host.file("/etc/apparmor.d/disabled")
        assert not folder.exists


@pytest.mark.parametrize(
    "aa_enforced",
    [
        "system_tor",
        "/usr/sbin/apache2",
        "/usr/sbin/apache2//DEFAULT_URI",
        "/usr/sbin/apache2//HANDLING_UNTRUSTED_INPUT",
        "/usr/sbin/tor",
    ],
)
def test_apparmor_enforced(host, aa_enforced):
    # FIXME: don't use awk, post-process it in Python
    awk = "awk '/[0-9]+ profiles.*enforce./" "{flag=1;next}/^[0-9]+.*/{flag=0}flag'"
    with host.sudo():
        c = host.check_output(f"aa-status | {awk}")
        assert aa_enforced in c


def test_aastatus_unconfined(host):
    """Ensure that there are no processes that are unconfined but have
    a profile"""

    # There should be 0 unconfined processes.
    expected_unconfined = 0

    unconfined_chk = str(
        f"{expected_unconfined} processes are unconfined but have" " a profile defined"
    )
    with host.sudo():
        aa_status_output = host.check_output("aa-status")
        assert unconfined_chk in aa_status_output


def test_aa_no_denies_in_syslog(host):
    """Ensure that there are no apparmor denials in syslog"""
    with host.sudo():
        f = host.file("/var/log/syslog")
        lines = f.content_string.splitlines()
    # syslog is very big, just print the denial lines
    found = []
    for line in lines:
        if 'apparmor="DENIED"' in line:
            if 'profile="ubuntu_pro_apt_news"' in line:
                # This failure is a known bug in Ubuntu that happens before SD
                # is installed and disables ubuntu-pro stuff. See
                # <https://github.com/freedomofpress/securedrop/issues/7385>.
                continue
            found.append(line)
    assert found == []
