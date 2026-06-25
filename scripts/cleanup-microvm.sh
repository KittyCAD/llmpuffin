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

aws() { uv run --extra microvm aws "$@"; }

export AWS_PROFILE="${AWS_PROFILE:-admin-executor}"

IMAGE_NAME="${1:?Usage: $0 <image-name> [region]}"
REGION="${2:-us-east-1}"

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
S3_BUCKET="llmpuffin-microvm-artifacts-${ACCOUNT_ID}"
ROLE_NAME="llmpuffin-microvm-build"
IMAGE_ARN="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:microvm-image:${IMAGE_NAME}"

# ── 1. Terminate running MicroVMs ──

echo "==> Listing MicroVMs for image '$IMAGE_NAME'..."

# Dump full response to find the correct field names
RAW=$(aws lambda-microvms list-microvms \
    --region "$REGION" \
    --image-identifier "$IMAGE_ARN" \
    --output json 2>/dev/null || echo '{}')

# Try common field patterns
MICROVM_IDS=$(echo "$RAW" | python3 -c "
import sys, json
data = json.load(sys.stdin)
# The response may use 'microvms', 'Microvms', or 'items' as the list key
items = data.get('microvms', data.get('Microvms', data.get('items', [])))
for item in items:
    mid = item.get('microvmId', item.get('MicrovmId', ''))
    if mid:
        print(mid)
" 2>/dev/null || true)

if [ -n "$MICROVM_IDS" ]; then
    for MVM_ID in $MICROVM_IDS; do
        echo "    Terminating $MVM_ID..."
        aws lambda-microvms terminate-microvm \
            --region "$REGION" \
            --microvm-identifier "$MVM_ID" 2>/dev/null || true
    done
    echo "    Waiting for terminations to complete..."
    sleep 10
else
    echo "    No MicroVMs found"
fi

# ── 2. Delete MicroVM image ──

echo "==> Deleting MicroVM image '$IMAGE_NAME'..."
aws lambda-microvms delete-microvm-image \
    --region "$REGION" \
    --image-identifier "$IMAGE_ARN" 2>/dev/null && echo "    Deleted" || echo "    Image not found or already deleted"

# ── 3. Remove S3 artifact ──

echo "==> Removing S3 artifact..."
aws s3 rm "s3://$S3_BUCKET/$IMAGE_NAME.zip" 2>/dev/null || echo "    Artifact not found"

echo "==> Deleting S3 bucket: $S3_BUCKET (and all contents)"
aws s3 rb "s3://$S3_BUCKET" --force 2>/dev/null || echo "    Bucket not found or already deleted"

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

aws iam delete-role --role-name "$ROLE_NAME" 2>/dev/null && echo "    Deleted" || echo "    Role not found"

echo ""
echo "Cleanup complete!"
