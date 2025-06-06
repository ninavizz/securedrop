#!/bin/bash
set -ex

# We create the virtualenv separately from the "pip install" commands below,
# to make error-reporting a bit more obvious. We also update beforehand,
# beyond what the system version provides, see #6317.
python3 -m venv /tmp/securedrop-app-code-i18n-ve
/tmp/securedrop-app-code-i18n-ve/bin/pip3 install -r \
<(echo "pip==25.0 \
--hash=sha256:8e0a97f7b4c47ae4a494560da84775e9e2f671d415d8d828e052efefb206b30b \
--hash=sha256:b6eb97a803356a52b2dd4bb73ba9e65b2ba16caa6bcb25a7497350a4e5859b65")

source /etc/os-release

# Install dependencies
/tmp/securedrop-app-code-i18n-ve/bin/pip3 install --no-deps --no-binary :all: --require-hashes -r requirements/${VERSION_CODENAME}/translation-requirements.txt

# Compile the translations
. /tmp/securedrop-app-code-i18n-ve/bin/activate
pybabel compile --directory translations/
