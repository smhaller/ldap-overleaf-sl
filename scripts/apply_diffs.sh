#!/bin/bash

set -e

DIFFS_DIR="ldap-overleaf-sl/sharelatex_diff"
ORI_DIR="ldap-overleaf-sl/sharelatex_ori"
PATCHED_DIR="ldap-overleaf-sl/sharelatex"

for diff_file in "$DIFFS_DIR"/*.diff; do
    filename=$(basename "$diff_file" ".diff")
    if [ "$filename" == ".gitkeep" ]; then
        continue
    fi

    original_file="$ORI_DIR/$filename"
    patched_file="$PATCHED_DIR/$filename"

    if [ -f "$original_file" ]; then
        cp "$original_file" "$patched_file"
        patch "$patched_file" "$diff_file"
    else
        echo "No original file for $filename in $ORI_DIR."
    fi
done
