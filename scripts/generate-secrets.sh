#!/bin/sh
# mid-radius-stack - fills random values for locally-generated .env secrets
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
set -eu

cd "$(dirname "$0")/.."

FORCE=0
if [ "${1:-}" = "--force" ]; then
  FORCE=1
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

set_secret() {
  var="$1"
  bytes="${2:-32}"
  if grep -qE "^${var}=" .env; then
    current="$(grep -E "^${var}=" .env | head -1 | cut -d'=' -f2-)"
    if [ -n "$current" ] && [ "$FORCE" -ne 1 ]; then
      echo "  $var already set, skipping (use --force to overwrite)"
      return
    fi
    value="$(openssl rand -hex "$bytes")"
    sed -i "s/^${var}=.*/${var}=${value}/" .env
  else
    value="$(openssl rand -hex "$bytes")"
    echo "${var}=${value}" >> .env
  fi
  echo "  $var generated"
}

echo "Generating local secrets in .env..."
set_secret POSTGRES_PASSWORD
set_secret REDIS_PASSWORD
# Gates device blocking (POST /block-device etc.) and the helper's
# /debug/ad-device, /debug/jamf-device endpoints - see intune-radius-helper's
# README "Device blocking" section. Left blank, those all fail closed rather
# than accept unauthenticated access, so there's no harm generating it even
# if you don't end up using those endpoints.
set_secret ADMIN_API_KEY

# Sites are user-defined (uncomment/add NAS_CIDR_<SITE> in .env yourself
# first - see .env.example) - this discovers whatever sites are already
# there and fills in a NAS_SECRET_<SITE> for each one missing it.
SITES="$(grep -oE '^NAS_CIDR_[A-Za-z0-9_]+=' .env | sed -E 's/^NAS_CIDR_//; s/=$//' | sort -u)"
if [ -z "$SITES" ]; then
  echo "  no NAS_CIDR_<SITE> entries found in .env - add your real sites first (see .env.example), then re-run this to fill in their NAS_SECRET_<SITE> values"
else
  for SITE in $SITES; do
    # 24 bytes -> 48 hex chars: some APs/switches cap RADIUS shared secret
    # length (commonly around 48-63 chars) - stay at exactly 48 rather than
    # the default 64 to be safe across hardware.
    set_secret "NAS_SECRET_${SITE}" 24
  done
fi

chmod 600 .env

cat <<'EOF'

Done. These still need to be filled in by hand (not generatable locally):
  TENANT_ID, CLIENT_ID, CLIENT_SECRET   - from the Entra app registration
  EXPECTED_ISSUER_CN                    - your PKI's issuing CA CN
  NAS_CIDR_<SITE> / VLAN_*_<SITE>       - your sites' NAS IPs/CIDRs and VLAN tags (see .env.example)
  URN_PREFIX                            - must match what your PKI issues in cert SAN URIs

Note: POSTGRES_PASSWORD/REDIS_PASSWORD only take effect on a fresh
./data/postgres. If Postgres has already initialized once with a different
password, regenerating here won't rotate it in the running database -
you'd need ALTER USER inside the container, or a fresh volume.
EOF
