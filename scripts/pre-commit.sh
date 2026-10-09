#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

files=()
while IFS= read -r -d '' file; do
    case "$file" in
        *.zig|*.zon) files+=("./$file") ;;
    esac
done < <(git diff --cached --name-only --diff-filter=ACMR -z)

if (( ${#files[@]} > 0 )); then
    for file in "${files[@]}"; do
        if [[ ! -f "$file" || -L "$file" ]]; then
            printf 'Cannot format non-regular staged file: %s\n' "$file" >&2
            exit 1
        fi
        if ! git diff --quiet -- "$file"; then
            printf 'Staged Zig file also has unstaged changes: %s\nStage the complete file or separate the changes before committing.\n' "$file" >&2
            exit 1
        fi
    done
    zig fmt "${files[@]}"
    git add -- "${files[@]}"
fi

exec mise run check
