#!/usr/bin/env bash
#
# Creates a Lambda MicroVM image.
#
# Shared resources (S3 bucket, IAM role) are created once and reused
# across all images. Each invocation uploads a new build artifact and
# creates a new MicroVM image.
#
# Usage:
#   ./scripts/setup-microvm-image.sh [--skip-image] <image-name> [region]
#
# Example:
#   ./scripts/setup-microvm-image.sh llmpuffin-workspace us-east-1
#   ./scripts/setup-microvm-image.sh --skip-image llmpuffin-workspace us-east-1

set -euo pipefail

aws() { uv run --extra microvm aws "$@"; }

export AWS_PROFILE="${AWS_PROFILE:-admin-executor}"

SKIP_IMAGE=false
if [ "${1:-}" = "--skip-image" ]; then
    SKIP_IMAGE=true
    shift
fi

IMAGE_NAME="${1:?Usage: $0 [--skip-image] <image-name> [region]}"
REGION="${2:-us-east-1}"

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
S3_BUCKET="llmpuffin-microvm-artifacts-${ACCOUNT_ID}"
ROLE_NAME="llmpuffin-microvm-build"
BUILD_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
IMAGE_ARN="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:microvm-image:${IMAGE_NAME}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

# ── 1. Ensure shared S3 bucket ──

echo "==> Ensuring S3 bucket: $S3_BUCKET"
if aws s3api head-bucket --bucket "$S3_BUCKET" 2>/dev/null; then
    echo "    Bucket already exists"
else
    aws s3api create-bucket \
        --bucket "$S3_BUCKET" \
        --region "$REGION" \
        $([ "$REGION" != "us-east-1" ] && echo "--create-bucket-configuration LocationConstraint=$REGION" || true)
    echo "    Created bucket"
fi

# ── 2. Ensure shared IAM build role ──

echo "==> Ensuring IAM role: $ROLE_NAME"

TRUST_POLICY=$(cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "lambda.amazonaws.com" },
    "Action": ["sts:AssumeRole", "sts:TagSession"]
  }]
}
EOF
)

PERMISSIONS_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::${S3_BUCKET}/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
EOF
)

if aws iam get-role --role-name "$ROLE_NAME" 2>/dev/null; then
    echo "    Role already exists, updating policies"
    aws iam update-assume-role-policy \
        --role-name "$ROLE_NAME" \
        --policy-document "$TRUST_POLICY"
else
    aws iam create-role \
        --role-name "$ROLE_NAME" \
        --assume-role-policy-document "$TRUST_POLICY" \
        --description "Lambda MicroVM build role for llmpuffin"
    echo "    Created role, waiting for propagation..."
    sleep 10
fi

aws iam put-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-name "${ROLE_NAME}-policy" \
    --policy-document "$PERMISSIONS_POLICY"
echo "    Permissions policy updated"

# ── 3. Build artifact ──

echo "==> Preparing MicroVM build artifact..."

cat > "$WORK_DIR/Dockerfile" <<'DOCKERFILE'
FROM python:3.13-slim-bookworm

RUN apt-get update && apt-get install -y \
    git \
    curl \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

RUN mkdir -p /src

RUN uv pip install --system \
    "llmpuffin @ git+https://github.com/KittyCAD/llmpuffin.git"

EXPOSE 8080

CMD ["llmpuffin-microvm-agent"]
DOCKERFILE

echo "==> Uploading to s3://$S3_BUCKET/$IMAGE_NAME.zip..."
cd "$WORK_DIR"
zip -r artifact.zip Dockerfile
aws s3 cp artifact.zip "s3://$S3_BUCKET/$IMAGE_NAME.zip"

# ── 4. MicroVM image ──

if [ "$SKIP_IMAGE" = true ]; then
    echo "==> Skipping image creation (--skip-image)"
else
    echo "==> Creating MicroVM image '$IMAGE_NAME'..."
    aws lambda-microvms create-microvm-image \
        --region "$REGION" \
        --name "$IMAGE_NAME" \
        --code-artifact "uri=s3://$S3_BUCKET/$IMAGE_NAME.zip" \
        --base-image-arn "arn:aws:lambda:$REGION:aws:microvm-image:al2023-1" \
        --build-role-arn "$BUILD_ROLE_ARN"

    echo "==> Waiting for image to reach CREATED state..."
    while true; do
        STATE=$(aws lambda-microvms get-microvm-image \
            --region "$REGION" \
            --image-identifier "$IMAGE_ARN" \
            --query 'state' --output text 2>/dev/null || echo "UNKNOWN")

        echo "    state: $STATE"
        if [ "$STATE" = "CREATED" ]; then
            echo "==> Image ready!"
            break
        elif [ "$STATE" = "CREATE_FAILED" ]; then
            echo "==> Image creation failed. Check CloudWatch logs: /aws/lambda/microvms/$IMAGE_NAME"
            exit 1
        fi
        sleep 10
    done
fi

echo ""
echo "Setup complete!"
echo ""
echo "Image ARN: $IMAGE_ARN"
echo ""
echo "Add to llmpuffin.toml:"
echo "  runtime = \"microvm\""
echo "  microvm_image_arn = \"$IMAGE_ARN\""
echo "  microvm_region = \"$REGION\""