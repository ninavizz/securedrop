#!/usr/bin/env python3

import argparse
import re
import secrets
import shutil
import sys
from pathlib import Path
from typing import Optional

CONFIG_PY = Path("/var/www/securedrop/config.py")
RQ_CONFIG_PY = Path("/var/www/securedrop/rq_config.py")
REDIS_CONF = Path("/etc/redis/redis.conf")

PYTHON_RE = re.compile(r"^REDIS_PASSWORD = ['\"](.*?)['\"]$")
REDIS_CONF_RE = re.compile(r"^requirepass (.*?)$")


def read_python_file(path: Path) -> Optional[str]:
    """Extract the password from a Python file"""
    if not path.exists():
        # rq_config.py might not exist yet
        return None
    contents = path.read_text()
    # Read in reverse because we want to look for the last matching line
    # since it'll take precedence in Python
    for line in contents.splitlines()[::-1]:
        match = PYTHON_RE.match(line)
        if match:
            return match.group(1)
    # Nothing found
    return None


def write_python_file(path: Path, password: str) -> None:
    """Set the new password in a Python file, removing any existing passwords"""
    if path.exists():
        lines = path.read_text().splitlines()
    else:
        lines = []
    # Take the existing file, remove any matching password lines, and then add
    # our new password at the end
    lines = [line for line in lines if not PYTHON_RE.match(line)]
    lines.append(f"REDIS_PASSWORD = '{password}'")
    if path == RQ_CONFIG_PY and not path.exists():
        # Ensure rq_config.py is created with the correct permissions
        path.write_text("")
        path.chmod(0o640)
        shutil.chown(path, "root", "www-data")

    path.write_text("\n".join(lines) + "\n")


def read_redis_conf(path: Path) -> Optional[str]:
    """Extract the password from our redis.conf file"""
    # n.b. we assume redis.conf exists, since the package should already
    # be installed
    contents = path.read_text()
    # Read in reverse because we want to look for the last matching line
    # since redis uses the last requirepass stanza
    for line in contents.splitlines()[::-1]:
        match = REDIS_CONF_RE.match(line)
        if match:
            return match.group(1)
    # Nothing found
    return None


def write_redis_conf(path: Path, password: str) -> None:
    """Set the new password in a redis.conf file, removing any existing passwords"""
    if not path.exists():
        raise RuntimeError("redis.conf does not already exist")
    lines = path.read_text().splitlines()
    # Take the existing file, remove any matching password lines, and then add
    # our new password at the end
    lines = [line for line in lines if not REDIS_CONF_RE.match(line)]
    lines.append(f"requirepass {password}")
    path.write_text("\n".join(lines) + "\n")


def generate_password() -> str:
    """
    Generate a base64-encoded, 32-byte random string

    This is roughly equivalent to `head -c 32 /dev/urandom | base64`
    """
    return secrets.token_urlsafe(32)


def check() -> bool:
    config_py = read_python_file(CONFIG_PY)
    rq_config_py = read_python_file(RQ_CONFIG_PY)
    redis_conf = read_redis_conf(REDIS_CONF)
    all_passwords = {config_py, rq_config_py, redis_conf}
    # If any are None, then we don't have the password set yet
    if None in all_passwords:
        return False
    # True if there's only one unique password
    return len(all_passwords) == 1


def reset() -> None:
    password = generate_password()
    write_python_file(CONFIG_PY, password)
    write_python_file(RQ_CONFIG_PY, password)
    write_redis_conf(REDIS_CONF, password)
    print("Redis password has been reset; please restart redis/apache2")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["check", "reset", "reset-if-needed"])
    args = parser.parse_args()

    if args.mode == "check":
        if check():
            print("Yay, all three passwords are the same!")
        else:
            print("Error: Passwords are not all the same!")
            sys.exit(1)
    elif args.mode == "reset":
        reset()
    elif args.mode == "reset-if-needed":
        if not check():
            reset()
        else:
            print("All three passwords are the same; nothing changed")
    else:
        # should be unreachable, but just in case
        raise RuntimeError(f"unknown mode: {args.mode}")


if __name__ == "__main__":
    main()
