#!/bin/bash

set -e

CONTAINER_FILE_PATHS=(
    "/overleaf/services/web/app/src/Features/Authentication/AuthenticationManager.js"
    "/overleaf/services/web/app/src/Features/Authentication/AuthenticationController.js"
    "/overleaf/services/web/app/src/Features/Contacts/ContactController.js"
    "/overleaf/services/web/app/src/Features/Project/ProjectEditorHandler.js"
    "/overleaf/services/web/app/src/router.js"
    "/overleaf/services/web/app/views/user/settings.pug"
    "/overleaf/services/web/app/views/user/login.pug"
    "/overleaf/services/web/app/views/layout/navbar.pug"
    "/overleaf/services/web/app/views/layout/navbar-marketing.pug"
    "/overleaf/services/web/app/views/admin/index.pug"
    "/overleaf/services/web/app/views/admin/index.pug"
)

FILENAMES=(
    "AuthenticationManager.js"
    "AuthenticationController.js"
    "ContactController.js"
    "ProjectEditorHandler.js"
    "router.js"
    "settings.pug"
    "login.pug"
    "navbar.pug"
    "navbar-marketing.pug"
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

CONTAINER_NAME="tmp_sharelatex_for_extract_files"
IMAGE="sharelatex/sharelatex:$VERSION"

echo "Starting Docker container \"$CONTAINER_NAME\" with image \"$IMAGE\"..."
if [ ! "$(docker ps -q -f name=^/${CONTAINER_NAME}$)" ]; then
    if [ "$(docker ps -aq -f status=exited -f name=^/${CONTAINER_NAME}$)" ]; then
        echo "Removing stopped container with same name..."
        docker rm $CONTAINER_NAME
    fi
else
    echo "Error: A container with the name $CONTAINER_NAME already exists."
    exit 1
fi
docker run -d --name $CONTAINER_NAME $IMAGE

echo "Waiting for container to start up..."
sleep 10

for i in "${!CONTAINER_FILE_PATHS[@]}"; do
    file_path="${CONTAINER_FILE_PATHS[i]}"
    new_filename="${FILENAMES[i]}"
    new_target_path="$HOST_TARGET_PATH/$new_filename"
    docker cp $CONTAINER_NAME:$file_path $new_target_path
done

echo "Stopping and removing container..."
docker stop $CONTAINER_NAME
docker rm $CONTAINER_NAME
