#!/bin/bash

set -e

CONTAINER_FILE_PATHS=(
    "/overleaf/services/web/app/src/Features/Authentication/AuthenticationManager.js"
    "/overleaf/services/web/app/src/Features/Authentication/AuthenticationController.js"
    "/overleaf/services/web/app/src/Features/Contacts/ContactController.mjs"
    "/overleaf/services/web/app/src/Features/Project/ProjectEditorHandler.js"
    "/overleaf/services/web/app/src/router.mjs"
    "/overleaf/services/web/app/views/user/login.pug"
    "/overleaf/services/web/app/views/layout/navbar-marketing.pug"
    "/overleaf/services/web/app/views/layout/navbar-marketing-bootstrap-5.pug"
    "/overleaf/services/web/app/views/admin/index.pug"
    "/overleaf/services/web/app/views/admin/index.pug"
)

FILENAMES=(
    "AuthenticationManager.js"
    "AuthenticationController.js"
    "ContactController.js"
    "ProjectEditorHandler.js"
    "router.js"
    "login.pug"
    "navbar-marketing.pug"
    "navbar-marketing-bootstrap-5.pug"
    "admin-index.pug"
    "admin-sysadmin.pug"
)

if [ "${#CONTAINER_FILE_PATHS[@]}" -ne "${#FILENAMES[@]}" ]; then
    echo "Error: The number of source files and target filenames does not match."
    exit 1
fi

HOST_TARGET_PATH="ldap-overleaf-sl/sharelatex_ori"

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 [version]"
    exit 1
else
    VERSION=$1
fi

mkdir -p "$HOST_TARGET_PATH"
IMAGE="sharelatex/sharelatex:$VERSION"

echo "Creating stopped container from image \"$IMAGE\"..."
CONTAINER_ID=$(docker create "$IMAGE")
trap 'docker rm "$CONTAINER_ID" >/dev/null' EXIT

for i in "${!CONTAINER_FILE_PATHS[@]}"; do
    file_path="${CONTAINER_FILE_PATHS[i]}"
    new_filename="${FILENAMES[i]}"
    new_target_path="$HOST_TARGET_PATH/$new_filename"
    docker cp "$CONTAINER_ID:$file_path" "$new_target_path"
done

touch "$HOST_TARGET_PATH/TrackChangesController.js"
echo "Extraction complete."
