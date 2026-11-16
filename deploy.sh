#!/bin/sh
# Deploy a kirkware-py-inspector app, stamping the live git origin/commit into
# a generated manifest so the running app can report where it came from.
#
#   ./deploy.sh cody                        # root manifest.yml -> app kirkware-py-inspector
#   ./deploy.sh cody-k8s manifests/pyi-fs4-k8s.yml
#
# Args: SPACE [MANIFEST]  (MANIFEST defaults to <repo>/manifest.yml)
set -eu

SPACE="$1"
MANIFEST="${2:-$(dirname "$0")/manifest.yml}"
cf target -o kirkware-devs -s "$SPACE"

ORIGIN="$(git config --get remote.origin.url || echo unknown)"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

APPNAME="$(basename "$MANIFEST" .yml)"
GEN="$(dirname "$0")/.gen-$APPNAME.yml"
awk -v origin="$ORIGIN" -v commit="$COMMIT" '
  /^    GIT_REPO_URL:/ { print "    GIT_REPO_URL: \"" origin "\""; next }
  /^    GIT_COMMIT:/   { print "    GIT_COMMIT: \"" commit "\""; next }
  { print }
' "$MANIFEST" > "$GEN"

cf push "$APPNAME" -f "$GEN"
rm -f "$GEN"
