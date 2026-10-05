#!/bin/bash

MODIFIED_DIR="ldap-overleaf-sl/sharelatex"
DIFFS_DIR="ldap-overleaf-sl/sharelatex_diff"
ORI_DIR="ldap-overleaf-sl/sharelatex_ori"

for modified_file in "$MODIFIED_DIR"/*; do
    [[ -f "$modified_file" ]] || continue
    filename=$(basename "$modified_file")
    raw_file="$ORI_DIR/$filename"

    if [ -f "$raw_file" ]; then
        diff_output="$DIFFS_DIR/${filename}.diff"
        diff "$raw_file" "$modified_file" > "$diff_output"
        status=$?
        if [[ "$status" -gt 1 ]]; then
            exit "$status"
        fi
    else
        echo "No matching file for $filename in $ORI_DIR."
    fi
done
