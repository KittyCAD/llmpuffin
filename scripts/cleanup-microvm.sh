#!/usr/bin/env bash
#
# Removes all AWS resources created by setup-microvm-image.sh:
#   1. Terminates all running/suspended MicroVMs for the image
#   2. Deletes the MicroVM image
#   3. Removes the S3 build artifact
#   4. Deletes the S3 bucket (if empty)
#   5. Removes the IAM build role and its inline policies
#
# Usage:
#   ./scripts/cleanup-microvm.sh <image-name> [region]
#
# Example:
#   ./scripts/cleanup-microvm.sh llmpuffin-workspace us-east-1

set -euo pipefail

alias aws='uv run --extra microvm aws'

export AWS_PROFILE="${AWS_PROFILE}"

IMAGE_NAME="${1:?Usage: $0 <image-name> [region]}"
REGION="${2:-us-east-1}"

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
S3_BUCKET="llmpuffin-microvm-artifacts-${ACCOUNT_ID}"
ROLE_NAME="llmpuffin-microvm-build"
IMAGE_ARN="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:microvm-image:${IMAGE_NAME}"

# ── 1. Terminate running MicroVMs ──

echo "==> Listing MicroVMs for image '$IMAGE_NAME'..."
MICROVM_IDS=$(uvx --from awscli aws lambda-microvms list-microvms \
    --region "$REGION" \
    --image-identifier "$IMAGE_ARN" \
    --query 'microvms[].microvmId' --output text 2>/dev/null || true)

if [ -n "$MICROVM_IDS" ]; then
    for MVM_ID in $MICROVM_IDS; do
        echo "    Terminating $MVM_ID..."
        uvx --from awscli aws lambda-microvms terminate-microvm \
            --region "$REGION" \
            --microvm-identifier "$MVM_ID" 2>/dev/null || true
    done
    echo "    Waiting for terminations to complete..."
    sleep 5
else
    echo "    No MicroVMs found"
fi

# ── 2. Delete MicroVM image ──

echo "==> Deleting MicroVM image '$IMAGE_NAME'..."
uvx --from awscli aws lambda-microvms delete-microvm-image \
    --region "$REGION" \
    --image-identifier "$IMAGE_ARN" 2>/dev/null || echo "    Image not found or already deleted"

# ── 3. Remove S3 artifact ──

echo "==> Removing S3 artifact..."
aws s3 rm "s3://$S3_BUCKET/$IMAGE_NAME.zip" 2>/dev/null || echo "    Artifact not found"

# Delete bucket if empty
REMAINING=$(aws s3 ls "s3://$S3_BUCKET/" 2>/dev/null | wc -l || echo 0)
if [ "$REMAINING" -eq 0 ]; then
    echo "==> Deleting empty S3 bucket: $S3_BUCKET"
    aws s3api delete-bucket --bucket "$S3_BUCKET" --region "$REGION" 2>/dev/null || echo "    Bucket not found"
else
    echo "==> Bucket $S3_BUCKET still has $REMAINING objects, skipping deletion"
fi

# ── 4. Remove IAM role ──

echo "==> Removing IAM role: $ROLE_NAME"

# Delete all inline policies first (required before role deletion)
POLICIES=$(aws iam list-role-policies \
    --role-name "$ROLE_NAME" \
    --query 'PolicyNames[]' --output text 2>/dev/null || true)

for POLICY in $POLICIES; do
    echo "    Deleting inline policy: $POLICY"
    aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY"
done

aws iam delete-role --role-name "$ROLE_NAME" 2>/dev/null || echo "    Role not found"

echo ""
echo "Cleanup complete!"
