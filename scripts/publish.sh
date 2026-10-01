#!/usr/bin/env bash
set -euo pipefail

dist="$(cd "${1:-dist}" && pwd)"
test -s "$dist/manifest.json"
scratch="$(mktemp -d)"
publish="$scratch/release"
cleanup() {
  git worktree remove --force "$publish" 2>/dev/null || true
  rmdir "$scratch" 2>/dev/null || true
}
trap cleanup EXIT

if test -n "$(git ls-remote --heads origin refs/heads/release)"; then
  git fetch origin release
  git worktree add --detach "$publish" FETCH_HEAD
else
  git worktree add --detach "$publish" HEAD
  git -C "$publish" checkout --orphan release
  git -C "$publish" rm -rf --ignore-unmatch .
fi

rsync -a --delete --exclude=.git "$dist/" "$publish/"
git -C "$publish" add --all
if git -C "$publish" diff --cached --quiet; then
  echo "Generated files are unchanged."
  exit 0
fi

upstream_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["upstream"]["sha"])' "$dist/manifest.json")"
git -C "$publish" -c user.name='github-actions[bot]' \
  -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
  commit -m "Sync MetaCubeX rules ${upstream_sha:0:12}"
git -C "$publish" push origin HEAD:refs/heads/release
