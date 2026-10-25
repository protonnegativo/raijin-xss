#!/usr/bin/env bash
# Tags HEAD with the next release and creates its GitHub Release.
# Usage: .github/release.sh [patch|minor|major] [base-commit]
# With a base commit, it skips when base..HEAD only touched files that do not change the binary.
# Needs GH_TOKEN and push access; release.yml and the drift job call it.
set -euo pipefail

bump=${1:-patch}
base=${2:-}

if [ -n "$(git tag --points-at HEAD 'v*')" ]; then
  echo "HEAD is already tagged $(git tag --points-at HEAD 'v*'); nothing to release"
  exit 0
fi

if [ -n "$base" ] && git cat-file -e "$base^{commit}" 2>/dev/null; then
  # engines.json is embedded in the binary, so it releases; fixtures, docs and CI do not.
  changed=$(git diff --name-only "$base" HEAD | grep -vE '^bench/fixtures/|\.md$|^docs/|^\.github/' || true)
  if [ -z "$changed" ]; then
    echo "only fixtures, docs or CI changed since $base; nothing to release"
    exit 0
  fi
fi

latest=$(git tag --list 'v*' --sort=-v:refname | head -1)
if [ -z "$latest" ]; then
  next=v0.1.0
else
  IFS=. read -r major minor patch <<<"${latest#v}"
  patch=${patch%%[-+]*}
  case $bump in
    major) next=v$((major + 1)).0.0 ;;
    minor) next=v$major.$((minor + 1)).0 ;;
    patch) next=v$major.$minor.$((patch + 1)) ;;
    *) echo "unknown bump: $bump (patch, minor or major)" >&2; exit 1 ;;
  esac
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git tag -a "$next" -m "$next"
git push origin "$next"
gh release create "$next" --generate-notes --title "$next"
echo "released $next"
