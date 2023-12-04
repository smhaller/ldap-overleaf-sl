#!/bin/bash

MODIFIED_DIR="ldap-overleaf-sl/sharelatex"
DIFFS_DIR="ldap-overleaf-sl/sharelatex_diff"
ORI_DIR="ldap-overleaf-sl/sharelatex_ori"

for filename in $(ls $MODIFIED_DIR); do
    raw_file="$ORI_DIR/$filename"

    if [ -f "$raw_file" ]; then
        diff_output="$DIFFS_DIR/${filename}.diff"
        diff "$raw_file" "$MODIFIED_DIR/$filename" > "$diff_output"
    else
        echo "No matching file for $filename in $ORI_DIR."
    fi
done
