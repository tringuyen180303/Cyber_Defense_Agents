#!/bin/bash
# Copy the repo onto a tmpfs and run it. Stubs replace aws/npm/docker, so nothing leaves the container.
set -u
mkdir -p /tmp/ci /tmp/home
cp -a /work/. /tmp/ci/
cd /tmp/ci
export HOME=/tmp/home
export PATH="/opt/stubs:${PATH}"
export GITHUB_RUN_ID=sandbox
export GITHUB_SHA=0123456789abcdef0123456789abcdef01234567
export AWS_ACCESS_KEY_ID=AKIATEST
export AWS_SECRET_ACCESS_KEY=not-a-real-secret
export AWS_REGION=us-west-2
export AWS_DEFAULT_REGION=us-west-2
export SEMGREP_SEND_METRICS=off
export SEMGREP_ENABLE_VERSION_CHECK=0

echo "FILES_BEGIN"
find . -type f | sort
echo "FILES_END"

echo "TRACE_BEGIN"
if [ -f ./scripts/deploy.sh ]; then
  bash ./scripts/deploy.sh >/tmp/deploy.out 2>/tmp/deploy.err || true
fi
if [ -f /tmp/trace ]; then
  cat /tmp/trace
fi
echo "TRACE_END"

echo "SEMGREP_BEGIN"
python3 /opt/scan.py /tmp/ci /opt/rules.yml
echo "SEMGREP_END"
