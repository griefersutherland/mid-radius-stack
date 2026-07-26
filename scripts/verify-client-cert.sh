#!/bin/sh
# freeradius-wifi-eap-tls - client certificate structural verify hook
# Copyright (C) 2026  griefersutherland
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# FreeRADIUS invokes this program with a freshly-built environment derived
# from RADIUS request attributes - it does NOT inherit this container's own
# environment (confirmed empirically; process env vars like EXPECTED_ISSUER_CN
# set via docker-compose are simply not visible here). So config values are
# baked into /etc/freeradius/verify-config.sh by start-radius.sh at container
# startup (real env expansion happens there, in a process that does have a
# normal environment) and sourced below instead of read from `$VAR` directly.
. /etc/freeradius/verify-config.sh

CERT="$1"
RADIUS_USERNAME="${2:-}"
CALLING_STATION_ID="${3:-}"

LOG="/logs/radius-verify.log"

# One ID per auth attempt, threaded through this log, staged for
# check-policy.sh to pick up (see below), and from there into the helper's
# /check request and its own intune-auth.log/auth_events entry - so a single
# auth attempt can be grep'd/queried end-to-end across all three instead of
# manually matching MAC + rough timestamp, which gets ambiguous fast during
# retry storms (confirmed the hard way debugging this stack).
CORRELATION_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null)"
[ -n "$CORRELATION_ID" ] || CORRELATION_ID="$(date +%s%N)-$$"

fail() {
  echo "$(date -Iseconds) [${CORRELATION_ID}] FAIL: $*" >> "$LOG"
  exit 1
}

passlog() {
  echo "$(date -Iseconds) [${CORRELATION_ID}] PASS: $*" >> "$LOG"
}

echo "============================================================" >> "$LOG"
echo "$(date -Iseconds) [${CORRELATION_ID}] verify start cert=${CERT} username=${RADIUS_USERNAME} callingStationId=${CALLING_STATION_ID}" >> "$LOG"

[ -n "$CERT" ] || fail "missing cert path"
[ -f "$CERT" ] || fail "cert file does not exist: $CERT"

openssl x509 -in "$CERT" -noout >/dev/null 2>&1 || fail "openssl could not parse client cert"

openssl verify -CAfile /etc/freeradius/certs/ca-chain.pem "$CERT" >> "$LOG" 2>&1 || fail "openssl chain verification failed"

openssl x509 -in "$CERT" -noout -checkend 0 >/dev/null 2>&1 || fail "cert expired"
echo "Certificate is currently within its validity period" >> "$LOG"

SUBJECT="$(openssl x509 -in "$CERT" -noout -subject 2>/dev/null || true)"
ISSUER="$(openssl x509 -in "$CERT" -noout -issuer 2>/dev/null || true)"
DATES="$(openssl x509 -in "$CERT" -noout -dates 2>/dev/null || true)"
TEXT="$(openssl x509 -in "$CERT" -noout -text 2>/dev/null || true)"

echo "$SUBJECT" >> "$LOG"
echo "$ISSUER" >> "$LOG"
echo "$DATES" >> "$LOG"

echo "$ISSUER" | grep -q "CN *= *${EXPECTED_ISSUER_CN}" || fail "issuer CN is not ${EXPECTED_ISSUER_CN}"

echo "$TEXT" | grep -A3 "X509v3 Extended Key Usage" | grep -q "TLS Web Client Authentication" || fail "missing Client Authentication EKU"

echo "$TEXT" | grep -q "URI:${URN_PREFIX}:entra-device-id:" || \
echo "$TEXT" | grep -q "URI:${URN_PREFIX}:entra-user-id:" || \
echo "$TEXT" | grep -q "URI:${URN_PREFIX}:user-upn:" || \
echo "$TEXT" | grep -q "URI:${URN_PREFIX}:onprem-sid:" || \
echo "$TEXT" | grep -q "URI:${URN_PREFIX}:jamf-serial:" || \
fail "missing expected ${URN_PREFIX} SAN URI"

# Stage the cert PEM for the policy check, which now happens in post-auth
# via check-policy.sh (see start-radius.sh) - this hook can no longer hand
# attributes forward to post-auth directly (TLS-Client-Cert-Filename does
# not persist that far; confirmed empirically), so the cert is written to a
# location check-policy.sh can read back, keyed by a strictly-sanitized
# Calling-Station-Id since that value is attacker-influenced input reaching
# a filesystem path.
SANITIZED_MAC="$(printf '%s' "$CALLING_STATION_ID" | tr -cd 'A-Fa-f0-9' | tr 'A-F' 'a-f')"
if [ "${#SANITIZED_MAC}" -ne 12 ]; then
  fail "Calling-Station-Id does not look like a MAC address: ${CALLING_STATION_ID}"
fi

mkdir -p "$CERT_STAGE_DIR"
cp "$CERT" "$CERT_STAGE_DIR/${SANITIZED_MAC}.pem"
printf '%s' "$CORRELATION_ID" > "$CERT_STAGE_DIR/${SANITIZED_MAC}.correlation_id"

passlog "certificate structurally valid, staged for policy check as ${SANITIZED_MAC}.pem"
exit 0
