#!/bin/bash
set -euo pipefail

MANIFEST="T0.json"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$DIR"

if [ ! -f "$MANIFEST" ]; then
    echo "Error: $MANIFEST not found" >&2
    exit 1
fi

echo "Verifying T0 package artifacts against $MANIFEST..."

ARTIFACTS_COUNT=$(jq '.artifacts | length' "$MANIFEST")
echo "Total artifacts to verify: $ARTIFACTS_COUNT"

ERRORS=0
SUCCESS=0

# Read artifacts from T0.json
while IFS= read -r artifact; do
    PATH_VAL=$(echo "$artifact" | jq -r '.path')
    EXPECTED_HASH=$(echo "$artifact" | jq -r '.sha256')

    if [ ! -f "$PATH_VAL" ]; then
        echo "FAIL: File not found: $PATH_VAL"
        ERRORS=$((ERRORS + 1))
        continue
    fi

    # Compute lowercase hex SHA-256
    ACTUAL_HASH=$(sha256sum "$PATH_VAL" | awk '{print $1}')

    if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
        echo "FAIL: Hash mismatch for $PATH_VAL"
        echo "  Expected: $EXPECTED_HASH"
        echo "  Actual:   $ACTUAL_HASH"
        ERRORS=$((ERRORS + 1))
    else
        echo "OK: $PATH_VAL"
        SUCCESS=$((SUCCESS + 1))
    fi
done < <(jq -c '.artifacts[]' "$MANIFEST")

echo "----------------------------------------"
if [ "$ERRORS" -gt 0 ]; then
    echo "Verification failed with $ERRORS error(s) ($SUCCESS passed)." >&2
    exit 1
else
    echo "All $SUCCESS artifacts verified successfully!"
    exit 0
fi
