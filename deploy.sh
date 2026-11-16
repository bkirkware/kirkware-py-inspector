#!/bin/sh
# Deploy kirkware-py-inspector to a space, stamping the live git origin/commit
# into a generated manifest so the running app can report where it came from.
#
#   ./deploy.sh                 # uses `cf target` as-is
#   ./deploy.sh cody            # targets kirkware-devs/cody first
set -eu

SPACE="${1:-}"
if [ -n "$SPACE" ]; then
  cf target -o kirkware-devs -s "$SPACE"
fi

ORIGIN="$(git config --get remote.origin.url || echo unknown)"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

MANIFEST="$(dirname "$0")/manifest.deploy.yml"
awk -v origin="$ORIGIN" -v commit="$COMMIT" '
  /^    GIT_REPO_URL:/ { print "    GIT_REPO_URL: \"" origin "\""; next }
  /^    GIT_COMMIT:/   { print "    GIT_COMMIT: \"" commit "\""; next }
  { print }
' "$(dirname "$0")/manifest.yml" > "$MANIFEST"

cf push kirkware-py-inspector -f "$MANIFEST"
rm -f "$MANIFEST"
