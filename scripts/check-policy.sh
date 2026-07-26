#!/bin/sh
# check-policy.sh - freeradius-wifi-eap-tls policy check, run from post-auth
# via %{exec:...} (see start-radius.sh). Reads the cert staged by
# verify-client-cert.sh, calls the helper's /check, and prints just the
# tier (access/untrust/reject) for unlang to switch on.
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

# Same environment caveat as verify-client-cert.sh: %{exec:...} gives this
# script a freshly-built environment derived from request attributes, not
# this container's own - so config values are baked in here too.
. /etc/freeradius/verify-config.sh

CALLING_STATION_ID="$1"
RADIUS_USERNAME="${2:-}"

fail_closed() {
  printf 'reject'
  exit 0
}

SANITIZED_MAC="$(printf '%s' "$CALLING_STATION_ID" | tr -cd 'A-Fa-f0-9' | tr 'A-F' 'a-f')"
[ "${#SANITIZED_MAC}" -eq 12 ] || fail_closed

CERT_FILE="$CERT_STAGE_DIR/${SANITIZED_MAC}.pem"
[ -f "$CERT_FILE" ] || fail_closed

CORRELATION_ID_FILE="$CERT_STAGE_DIR/${SANITIZED_MAC}.correlation_id"
CORRELATION_ID="$(cat "$CORRELATION_ID_FILE" 2>/dev/null || true)"

# RADIUS_USERNAME/CALLING_STATION_ID are passed via the environment (ENVIRON[]),
# not `awk -v` - awk's `-v var=value` assignments undergo their own escape-sequence
# interpretation (implementation-defined for sequences awk doesn't recognize,
# e.g. mawk - the actual awk in this image - passes a literal `\S` straight
# through), which is exactly the kind of surprise this needs to avoid when the
# value can contain arbitrary characters (a Windows supplicant sending
# `DOMAIN\user` as User-Name will otherwise break the JSON here).
REQUEST_JSON="$(RADIUS_USERNAME="$RADIUS_USERNAME" CALLING_STATION_ID="$CALLING_STATION_ID" CORRELATION_ID="$CORRELATION_ID" awk '
function jsonescape(s) {
  # gsub replacement text has its own backslash handling too: a
  # single escaped backslash in the replacement is a no-op (it means
  # "insert what matched"), so doubling a literal backslash needs
  # four backslashes here, not two - verified empirically against
  # this images own mawk, not assumed.
  gsub(/\\/, "\\\\\\\\", s)
  gsub(/"/, "\\\"", s)
  gsub(/\t/, "\\t", s)
  gsub(/\r/, "\\r", s)
  gsub(/\n/, "\\n", s)
  return s
}
BEGIN { printf("{"); printf("\"cert_pem\":\"") }
{ gsub(/\\/,"\\\\\\\\"); gsub(/"/,"\\\""); printf("%s\\n", $0) }
END {
  printf("\",")
  printf("\"radius_username\":\"%s\",", jsonescape(ENVIRON["RADIUS_USERNAME"]))
  printf("\"calling_station_id\":\"%s\",", jsonescape(ENVIRON["CALLING_STATION_ID"]))
  printf("\"correlation_id\":\"%s\"", jsonescape(ENVIRON["CORRELATION_ID"]))
  printf("}")
}
' "$CERT_FILE")"

RESPONSE="$(curl -sS --max-time 8 -X POST -H "Content-Type: application/json" \
  --data "$REQUEST_JSON" "$HELPER_URL" 2>/dev/null)"

rm -f "$CERT_FILE" "$CORRELATION_ID_FILE"

TIER="$(printf '%s' "$RESPONSE" | grep -oE '"tier"[[:space:]]*:[[:space:]]*"[a-z]+"' | sed -E 's/.*"([a-z]+)"$/\1/')"

case "$TIER" in
  access|untrust|reject) printf '%s' "$TIER" ;;
  *) printf 'reject' ;;
esac
