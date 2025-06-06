"""
Test redis is configured as desired
"""

import re

import pytest
import testutils

sdvars = testutils.securedrop_test_vars
testinfra_hosts = [sdvars.app_hostname]


def extract_password(host) -> str:
    f = host.file("/var/www/securedrop/rq_config.py")
    with host.sudo():
        contents = f.content_string
    print(contents)
    return re.search(r"^REDIS_PASSWORD = ['\"](.*?)['\"]$", contents).group(1)


def assert_password_works(host, password):
    # Run an authenticated PING
    response = host.run(
        f'bash -c \'echo "PING" | REDISCLI_AUTH="{password}" redis-cli\''
    ).stdout.strip()
    assert response == "PONG"


def test_auth_required(host):
    """
    Verify the redis server requires authentication
    """
    response = host.run("bash -c 'echo \"PING\" | redis-cli'").stdout.strip()
    assert response == "NOAUTH Authentication required."


def test_password_works(host):
    """
    Verify the redis password works
    """
    f = host.file("/var/www/securedrop/rq_config.py")
    with host.sudo():
        # First let's check file permissions
        assert f.is_file
        assert f.user == "root"
        assert f.group == "www-data"
        assert f.mode == 0o640
    # Get the password
    password = extract_password(host)
    assert_password_works(host, password)


def test_check(host):
    """All the redis passwords should be in sync"""
    with host.sudo():
        assert host.run("securedrop-set-redis-auth.py check").rc == 0


@pytest.mark.skip_in_prod
def test_check_fail(host):
    with host.sudo():
        old = extract_password(host)
        try:
            cmd = host.run("echo 'REDIS_PASSWORD = \"wrong\"' > /var/www/securedrop/rq_config.py")
            assert cmd.rc == 0
            assert host.run("securedrop-set-redis-auth.py check").rc == 1
            # Verify reset-if-needed will fix it
            assert host.run("securedrop-set-redis-auth.py reset-if-needed").rc == 0
            assert host.run("systemctl restart redis-server").rc == 0
            assert host.run("systemctl restart apache2").rc == 0
            new = extract_password(host)
            assert old != new, "password changed"
            assert_password_works(host, new)
            with pytest.raises(AssertionError):
                # Old password no longer works
                assert_password_works(host, old)
        finally:
            # Reset to cleanup
            assert host.run("securedrop-set-redis-auth.py reset").rc == 0
            assert host.run("systemctl restart redis-server").rc == 0
            assert host.run("systemctl restart apache2").rc == 0


@pytest.mark.skip_in_prod
def test_reset(host):
    original = extract_password(host)
    with host.sudo():
        assert host.run("securedrop-set-redis-auth.py reset").rc == 0
        assert host.run("systemctl restart redis-server").rc == 0
        assert host.run("systemctl restart apache2").rc == 0

    new = extract_password(host)
    assert new != original, "password changed"

    assert_password_works(host, new)
    with pytest.raises(AssertionError):
        # Old password no longer works
        assert_password_works(host, original)

    # Now verify that reset-if-needed does nothing
    with host.sudo():
        assert host.run("securedrop-set-redis-auth.py reset-if-needed").rc == 0
    current = extract_password(host)
    assert current == new, "password not changed since it wasn't needed"
