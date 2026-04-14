#!/usr/bin/env bash
set -e

echo "Checking version..."
if ! git describe --tags --exact-match >/dev/null 2>&1; then
  echo "You are not on a tag. Aborting."
  exit 1
fi

TAG=$(git describe --tags --exact-match)
echo "Releasing version: $TAG"

echo "Checking for uncommitted changes..."
if [ -n "$(git status --porcelain)" ]; then
  echo "Working directory not clean. Commit first."
  exit 1
fi

echo "Checking environment..."
if [ -z "$MAVEN_GPG_PASSPHRASE" ]; then
  echo "MAVEN_GPG_PASSPHRASE not set"
  exit 1
fi

echo "Running license format..."
mvn -B -ntp license:format
git add -u

if [ -n "$(git status --porcelain)" ]; then
  echo "License headers updated. Commit and rerun."
  exit 1
fi

echo "Running tests..."
mvn -B -ntp clean verify

echo "Deploying..."
mvn -B -ntp -Prelease -DskipTests deploy

echo "Done."