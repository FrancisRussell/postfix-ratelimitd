#!/usr/bin/env bash
# Regenerates the throwaway CA/server cert/server key in this directory, used
# by tests/valkey_integration.rs's TLS test. Not secrets: this CA signs
# nothing outside this repo's own test suite. Run from anywhere; output always
# lands next to this script.
set -euo pipefail

cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

openssl req -x509 -newkey rsa:2048 -keyout "$work/ca.key" -out ca.crt -days 36500 -nodes \
  -subj "/CN=postfix-ratelimitd-test-fixture-ca"
openssl req -newkey rsa:2048 -keyout server.key -out "$work/server.csr" -nodes -subj "/CN=localhost"
openssl x509 -req -in "$work/server.csr" -CA ca.crt -CAkey "$work/ca.key" -CAcreateserial -out server.crt -days 36500 \
  -extfile <(echo "subjectAltName=IP:127.0.0.1,DNS:localhost")
rm -f ca.srl
