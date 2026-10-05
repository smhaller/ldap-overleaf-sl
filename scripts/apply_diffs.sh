#!/bin/bash

set -e

DIFFS_DIR="${DIFFS_DIR:-ldap-overleaf-sl/sharelatex_diff}"
ORI_DIR="${ORI_DIR:-ldap-overleaf-sl/sharelatex_ori}"
PATCHED_DIR="${PATCHED_DIR:-ldap-overleaf-sl/sharelatex}"

mkdir -p "$PATCHED_DIR"

for diff_file in "$DIFFS_DIR"/*.diff; do
    filename=$(basename "$diff_file" ".diff")
    if [ "$filename" == ".gitkeep" ]; then
        continue
    fi

    original_file="$ORI_DIR/$filename"
    patched_file="$PATCHED_DIR/$filename"

    if [ -f "$original_file" ]; then
        cp "$original_file" "$patched_file"
        if [[ -s "$diff_file" ]]; then
            patch --batch --fuzz=0 "$patched_file" "$diff_file"
        fi
    else
        echo "No original file for $filename in $ORI_DIR." >&2
        exit 1
    fi
done
