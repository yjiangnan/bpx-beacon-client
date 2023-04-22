#!/usr/bin/env bash
# Post install script for the UI .deb to place symlinks in places to allow the CLI to work similarly in both versions

set -e

ln -s /opt/bpx/resources/app.asar.unpacked/daemon/bpx /usr/bin/bpx || true
ln -s /opt/bpx/bpx-beacon-client /usr/bin/bpx-beacon-client || true
