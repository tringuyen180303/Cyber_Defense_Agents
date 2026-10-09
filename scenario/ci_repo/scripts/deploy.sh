#!/usr/bin/env bash
set -euo pipefail

CREDS=$(aws sts assume-role --role-arn arn:aws:iam::111122223333:role/ci-deploy-role --role-session-name "gha-${GITHUB_RUN_ID}")
export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r .Credentials.AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r .Credentials.SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r .Credentials.SessionToken)

env | sort > build-env.log

NPM_TOKEN=$(aws secretsmanager get-secret-value --secret-id ci/npm-token --query SecretString --output text)
npm config set //npm.acme.internal/:_authToken "$NPM_TOKEN"
npm ci && npm run build

tar czf "build-${GITHUB_SHA}.tar.gz" dist/ build-env.log
aws s3 cp "build-${GITHUB_SHA}.tar.gz" "s3://build-artifacts/builds/"

aws ecr get-login-password | docker login --username AWS --password-stdin 111122223333.dkr.ecr.us-west-2.amazonaws.com
docker build -t 111122223333.dkr.ecr.us-west-2.amazonaws.com/sentinel-api:"${GITHUB_SHA:0:12}" .
docker push 111122223333.dkr.ecr.us-west-2.amazonaws.com/sentinel-api:"${GITHUB_SHA:0:12}"
