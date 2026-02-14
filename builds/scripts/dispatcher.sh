#!/bin/sh
# prometheus-exporter build dispatcher script
# Analyzes git changes and submits build workflows for changed source or build files
#
# KEY DIFFERENCE from Media-Streaming/P2-Apps dispatchers:
# This repo IS the source code. Builds are triggered by:
#   1. Source code changes (.go files, go.mod, go.sum)
#   2. Dockerfile or build file changes
#   3. versions.yaml changes (bump or enabled)
#
# The image is always tagged with $COMMIT_SHA (the triggering commit),
# NOT a version/commit from versions.yaml.
#
# Required env vars:
#   COMMIT_SHA - Git commit SHA that triggered the build
#   REPO - GitHub repository (e.g., 509-Digital/prometheus-exporter)
#
# Expected to run in /workspace/src after git clone
set -e

cd /workspace/src

# Get list of changed files in this commit
CHANGED_FILES=$(git diff-tree --no-commit-id --name-only -r "$COMMIT_SHA")
echo "Changed files:"
echo "$CHANGED_FILES"
echo ""

VERSIONS_FILE="builds/versions.yaml"

if [ ! -f "$VERSIONS_FILE" ]; then
  echo "No builds/versions.yaml found"
  exit 0
fi

BUILDS_DIR="builds"
HARBOR_PROJECT=$(yq e ".harbor_project // \"library\"" "$VERSIONS_FILE")
echo "=== Processing: prometheus-exporter (harbor: $HARBOR_PROJECT) ==="

# Get list of apps defined in versions.yaml
APPS_IN_GROUP=$(yq e '.apps | keys | .[]' "$VERSIONS_FILE")

APPS_TO_BUILD=""

for app in $APPS_IN_GROUP; do
  ENABLED=$(yq e ".apps.${app}.enabled" "$VERSIONS_FILE")

  if [ "$ENABLED" != "true" ]; then
    echo "  Skipping $app (disabled)"
    continue
  fi

  SHOULD_BUILD=false

  # Check 1: Source code changes (.go files, go.mod, go.sum anywhere in the repo)
  if echo "$CHANGED_FILES" | grep -qE '\.(go)$|^go\.(mod|sum)$'; then
    echo "  $app: source code changed"
    SHOULD_BUILD=true
  fi

  # Check 2: Dockerfile or build file changes
  if [ "$SHOULD_BUILD" = "false" ] && echo "$CHANGED_FILES" | grep -q "^${BUILDS_DIR}/${app}/"; then
    echo "  $app: Dockerfile/build files changed"
    SHOULD_BUILD=true
  fi

  # Check 3: versions.yaml changes (bump or enabled)
  if [ "$SHOULD_BUILD" = "false" ] && echo "$CHANGED_FILES" | grep -q "^${VERSIONS_FILE}$"; then
    OLD_ENABLED=$(git show HEAD~1:"$VERSIONS_FILE" 2>/dev/null | yq e ".apps.${app}.enabled" - 2>/dev/null || echo "")
    OLD_BUMP=$(git show HEAD~1:"$VERSIONS_FILE" 2>/dev/null | yq e ".apps.${app}.bump // \"\"" - 2>/dev/null || echo "")
    NEW_BUMP=$(yq e ".apps.${app}.bump // \"\"" "$VERSIONS_FILE")

    if [ "$OLD_ENABLED" != "true" ]; then
      echo "  $app: newly enabled - will build"
      SHOULD_BUILD=true
    elif [ -n "$NEW_BUMP" ] && [ "$OLD_BUMP" != "$NEW_BUMP" ]; then
      echo "  $app: bump changed ($OLD_BUMP -> $NEW_BUMP) - forcing rebuild"
      SHOULD_BUILD=true
    fi
  fi

  if [ "$SHOULD_BUILD" = "true" ]; then
    # For source-code repos, always use the triggering commit SHA as the tag
    echo "  Will build: $app ($COMMIT_SHA) -> $HARBOR_PROJECT"
    APPS_TO_BUILD="${APPS_TO_BUILD}${app}:${COMMIT_SHA}:${HARBOR_PROJECT} "
  else
    echo "  Skipping $app (no changes)"
  fi
done
echo ""

if [ -z "$APPS_TO_BUILD" ]; then
  echo "No apps need building"
  exit 0
fi

# Submit build workflows for each app
for entry in $APPS_TO_BUILD; do
  APP=$(echo "$entry" | cut -d: -f1)
  BUILD_REF=$(echo "$entry" | cut -d: -f2)
  HARBOR_PROJECT=$(echo "$entry" | cut -d: -f3)

  DOCKERFILE_PATH="${BUILDS_DIR}/${APP}/Dockerfile"

  echo "Submitting build for $APP -> harbor.509.digital/$HARBOR_PROJECT/$APP"
  echo "  Dockerfile: $DOCKERFILE_PATH"
  echo "  Version: $BUILD_REF"

  cat <<EOF | kubectl create -f -
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: build-${APP}-
  namespace: argo
spec:
  workflowTemplateRef:
    name: build-prometheus-exporter
  arguments:
    parameters:
      - name: app
        value: "${APP}"
      - name: version
        value: "${BUILD_REF}"
      - name: dockerfile-path
        value: "${DOCKERFILE_PATH}"
      - name: harbor-project
        value: "${HARBOR_PROJECT}"
      - name: repo
        value: "${REPO}"
EOF
done

echo "All build workflows submitted"
