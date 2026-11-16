#!/bin/sh
# Deploy a kirkware-py-inspector app, stamping live provenance into a
# generated manifest so the running app can report where it came from:
#   GIT_REPO_URL / GIT_COMMIT  — git origin + HEAD
#   BUILDPACK_NAME / BUILDPACK_VERSION — org-resolved buildpack (name from
#     the manifest, version from the `cf buildpacks` filename for that
#     buildpack + stack)
#   APP_STACK — the manifest's stack (not visible from inside the droplet)
#
#   ./deploy.sh cody                        # root manifest.yml -> app kirkware-py-inspector
#   ./deploy.sh cody-k8s manifests/pyi-fs4-k8s.yml
#
# Args: SPACE [MANIFEST]  (MANIFEST defaults to <repo>/manifest.yml)
set -eu

SPACE="$1"
MANIFEST="${2:-$(dirname "$0")/manifest.yml}"
cd "$(dirname "$0")"
cf target -o kirkware-devs -s "$SPACE"

ORIGIN="$(git config --get remote.origin.url || echo unknown)"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

# Stack + buildpack straight from the manifest being deployed.
STACK="$(awk -F': *' '$1 ~ /^ *stack$/ {print $2; exit}' "$MANIFEST")"
BUILDPACK="$(awk '/^ *buildpacks:/{f=1;next} f && $1=="-"{print $2; exit} f && $1!="-"{f=0}' "$MANIFEST")"

# Version as the org resolves it: filename column of `cf buildpacks`,
# matching buildpack name + stack. Empty when the org has no such buildpack.
BUILDPACK_VERSION=""
if [ -n "$BUILDPACK" ]; then
  BUILDPACK_VERSION="$(cf buildpacks 2>&1 | awk -v bp="$BUILDPACK" -v st="$STACK" '
    $2 == bp && $3 == st { f = $7; sub(/.*-v/, "", f); sub(/\.zip$/, "", f); print f; exit }
  ')"
fi

APPNAME="$(basename "$MANIFEST" .yml)"
GEN="$(dirname "$0")/.gen-$APPNAME.yml"
awk -v origin="$ORIGIN" -v commit="$COMMIT" \
    -v stack="$STACK" -v bpname="$BUILDPACK" -v bpver="$BUILDPACK_VERSION" '
  /^    GIT_REPO_URL:/       { print "    GIT_REPO_URL: \"" origin "\""; next }
  /^    GIT_COMMIT:/         { print "    GIT_COMMIT: \"" commit "\""; next }
  /^    BUILDPACK_NAME:/     { print "    BUILDPACK_NAME: \"" bpname "\""; next }
  /^    BUILDPACK_VERSION:/  { print "    BUILDPACK_VERSION: \"" bpver "\""; next }
  /^    APP_STACK:/          { print "    APP_STACK: \"" stack "\""; next }
  { print }
' "$MANIFEST" > "$GEN"

echo "stamping: stack=$STACK buildpack=$BUILDPACK v$BUILDPACK_VERSION commit=$COMMIT"
cf push "$APPNAME" -f "$GEN"
rm -f "$GEN"
