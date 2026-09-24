#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"

git_repo() {
  local owner
  owner="$(stat -c %U "$root")"
  if [[ "$owner" != root ]]; then
    runuser -u "$owner" -- git -C "$root" "$@"
  else
    git -C "$root" "$@"
  fi
}

# This first phase deliberately contains no project dependencies.  Updating the
# checkout can replace this file and update-common.sh, so execute the freshly
# downloaded updater instead of continuing with an old script in memory.
if [[ "${1:-}" != "--sources-updated" ]]; then
  [[ ${EUID} -eq 0 ]] || { echo "Das Update muss als root ausgefuehrt werden." >&2; exit 1; }
  command -v git >/dev/null || { echo "git wurde nicht gefunden." >&2; exit 1; }
  git_repo rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
    echo "Das Online-Update muss aus einem Git-Checkout ausgefuehrt werden." >&2
    exit 1
  }
  [[ -z "$(git_repo status --porcelain --untracked-files=normal)" ]] || {
    echo "Der Git-Checkout enthaelt lokale Aenderungen. Update abgebrochen." >&2
    exit 1
  }

  remote="${CERTIFY_UPDATE_REMOTE:-origin}"
  echo "[1/6] Git-Sourcen und Release-Tags von ${remote} aktualisieren ..."
  git_repo fetch --tags --prune "$remote"

  if [[ -n "${CERTIFY_UPDATE_REF:-}" ]]; then
    target="$(git_repo rev-parse --verify "${CERTIFY_UPDATE_REF}^{commit}")" || {
      echo "Update-Referenz nicht gefunden: ${CERTIFY_UPDATE_REF}" >&2; exit 1;
    }
    git_repo merge-base --is-ancestor HEAD "$target" || {
      echo "${CERTIFY_UPDATE_REF} ist kein Fast-Forward des lokalen Quellstands." >&2; exit 1;
    }
    git_repo checkout --detach "$target"
  else
    branch="$(git_repo symbolic-ref --quiet --short HEAD)" || {
      echo "Der Checkout ist detached. CERTIFY_UPDATE_REF muss auf einen neueren Tag oder Commit zeigen." >&2
      exit 1
    }
    # Pull from the explicitly selected remote, even when no upstream was set.
    git_repo merge --ff-only "refs/remotes/${remote}/${branch}"
  fi

  exec "$root/packaging/update-online.sh" --sources-updated
fi

shift
# shellcheck source=packaging/update-common.sh
source "$root/packaging/update-common.sh"
certify_update "$root"
