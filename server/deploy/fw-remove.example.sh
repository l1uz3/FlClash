#!/bin/sh
# Example PUNCH_FW_REMOVE hook. The coordinator runs it with one argument, the CIDR to remove from
# the firewalled server's allow-list (e.g. 203.0.113.0/24), and logs its first output line.
#
# Exit 0 only once the entry is really gone: the coordinator waits PUNCH_REMOVE_WAIT seconds after
# this returns and then has clients open the tuples that must NOT be allow-listed. Entries whose
# removal fails are retried by the coordinator's janitor after about a minute.
#
# Replace the body with your provider's API or console call. Keep credentials out of this file:
# read them from a root-only environment file instead.
set -eu
cidr="$1"

# set -a; . /etc/punch/fw.env; set +a
# curl -fsS -X DELETE -H "Authorization: Bearer $FW_API_TOKEN" \
#   "https://api.example.com/v1/firewall/allow/$(printf %s "$cidr" | sed 's#/#%2F#')"

echo "fw-remove: not configured, cannot remove $cidr" >&2
exit 1
