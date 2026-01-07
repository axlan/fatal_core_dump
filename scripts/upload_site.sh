#! /usr/bin/env bash
set -e

if [ -n "$(git status --porcelain)" ]; then
    echo "Warning: Git repository is dirty. Aborting."
    exit 1
fi

VERSION=$(git describe --tags)
sed -i "s/@VERSION@/$VERSION/g" site/*.html
echo "Injected version $VERSION into HTML files in $BUILD_DIR"

aws s3 sync --profile robopenguin --delete site/ s3://www.robopenguins.com/fatal_core_dump/

aws cloudfront create-invalidation --profile robopenguin --distribution-id E3SR3H7C34DQ6Z --paths "/fatal_core_dump/*"

git reset HEAD --hard
