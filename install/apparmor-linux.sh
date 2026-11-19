#!/bin/sh
# Lets nia-edge's binary alone create user namespaces where AppArmor
# restricts them (Ubuntu 23.10 and later): its simulations of an agent's
# commands need them. Elsewhere it changes nothing.
#
#   sudo install/apparmor-linux.sh [binary] [profile-name]
#
# The profile is the one Ubuntu documents for such programs: unconfined,
# with the userns rule (abi 4.0). Any user who runs this binary can then
# make a user namespace with it, as with rootless podman or bubblewrap.
set -eu

BINARY=${1:-/usr/local/bin/nia-edge}
NAME=${2:-nia-edge}
PROFILE=/etc/apparmor.d/$NAME

restricted=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)
if [ "$restricted" != 1 ]; then
  echo "apparmor: user namespaces are not restricted here, nothing to do"
  exit 0
fi
# The restriction leans on unconfined profiles that may allow userns.
if [ "$(cat /sys/kernel/security/apparmor/features/policy/unconfined_restrictions/userns 2>/dev/null || echo 0)" != 1 ]; then
  echo "apparmor: this kernel cannot let one program create user namespaces: simulated commands will be refused" >&2
  exit 1
fi
command -v apparmor_parser >/dev/null || { echo "apparmor: apparmor_parser is required" >&2; exit 1; }
case $BINARY in
  /*) ;;
  *) echo "apparmor: the binary must be an absolute path" >&2; exit 2 ;;
esac

cat > "$PROFILE" <<PROFILE
# nia-edge: its simulations of an agent's commands need user namespaces.
abi <abi/4.0>,
include <tunables/global>

profile $NAME $BINARY flags=(unconfined) {
  userns,

  # Site-specific additions and overrides. See local/README for details.
  include if exists <local/$NAME>
}
PROFILE
chmod 0644 "$PROFILE"
apparmor_parser -r "$PROFILE"
echo "apparmor: $BINARY may create user namespaces ($PROFILE)"
