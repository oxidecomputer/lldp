#!/usr/bin/env bash

set -o pipefail
set -o errexit

SOURCE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

function usage {
    echo "usage: $0 [-c COMMIT] [-n]"
    echo
    echo "  -c COMMIT   Ask to update Dendrite to a specific commit."
    echo "              If this is unset, Github is queried."
    echo "  -n          Dry-run"
    exit 1
}

REPO="oxidecomputer/dendrite"


URL="https://buildomat.eng.oxide.computer/public/file/oxidecomputer/dendrite/openapi/$COMMIT/dpd.json"
LOCAL_FILE="$DOWNLOAD_DIR/dpd-$COMMIT.json"
# Get the SHA for a Buildomat artifact.
#
# Note the "series" component of the Buildomat public file hierarchy
# is the optional 4th argument, and defaults to "image".
function get_sha {
    REPO="$1"
    COMMIT="$2"
    ARTIFACT="$3"
    SERIES="${4:-image}"
    curl -fsS "https://buildomat.eng.oxide.computer/public/file/$REPO/$SERIES/$COMMIT/$ARTIFACT.sha256.txt"
}

function get_latest_commit_from_gh {
    REPO="$1"
    TARGET_COMMIT="$2"
    if [[ -z "$TARGET_COMMIT" ]]; then
        curl -fsS "https://buildomat.eng.oxide.computer/public/branch/$REPO/main"
    else
        echo "$TARGET_COMMIT"
    fi
}

function update_openapi {
    TARGET_COMMIT="$1"
    DRY_RUN="$2"
    SHA=$(get_sha "$REPO" "$TARGET_COMMIT" "dpd.json" "openapi")
    OUTPUT=$(printf "COMMIT=\"%s\"\nSHA2=\"%s\"\n" "$TARGET_COMMIT" "$SHA")

    if [ -n "$DRY_RUN" ]; then
        OPENAPI_PATH="/dev/null"
    else
        OPENAPI_PATH="$SOURCE_DIR/dendrite_openapi_version"
    fi
    echo "Updating Dendrite OpenAPI from: $TARGET_COMMIT"
    set -x
    echo "$OUTPUT" > "$OPENAPI_PATH"
    set +x
}

function main {
    TARGET_COMMIT=""
    DRY_RUN=""
    while getopts "c:n" o; do
      case "${o}" in
        c)
          TARGET_COMMIT="$OPTARG"
          ;;
        n)
          DRY_RUN="yes"
          ;;
        *)
          usage
          ;;
      esac
    done

    TARGET_COMMIT=$(get_latest_commit_from_gh "$REPO" "$TARGET_COMMIT")
    update_openapi "$TARGET_COMMIT" "$DRY_RUN"
}

main "$@"
