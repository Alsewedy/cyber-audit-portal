#!/bin/bash

# Configuration
KEYCLOAK_URL="http://192.168.30.10:8080/realms/secure-finance/protocol/openid-connect/token"
API_BASE_URL="http://localhost:3050/api"
CLIENT_ID="report-verifier-client"
CLIENT_SECRET="${REPORT_VERIFIER_CLIENT_SECRET}"

if [ -z "$CLIENT_SECRET" ]; then
    echo "Missing REPORT_VERIFIER_CLIENT_SECRET environment variable."
    exit 1
fi
echo "Starting Automated Verification Job (Shell)..."

#specify the correct grant_type
echo "Authenticating..."
RESPONSE=$(curl -s -X POST "$KEYCLOAK_URL" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET")

# Extract the token using jq
TOKEN=$(echo $RESPONSE | jq -r '.access_token')

if [ "$TOKEN" == "null" ] || [ -z "$TOKEN" ]; then
    echo "Failed to authenticate service account."
    exit 1
fi
echo "✓ Service Account Machine Token Acquired"

# Fetch all reports and use jq to filter for PENDING ones, returning just their IDs
PENDING_IDS=$(curl -s -H "Authorization: Bearer $TOKEN" "$API_BASE_URL/pending/report" | jq -r '.[] | select(.status=="PENDING") | .id')

if [ -z "$PENDING_IDS" ]; then
    echo "No pending reports found. Exiting."
    exit 0
fi

# Process and Verify each pending report
for ID in $PENDING_IDS; do
    echo "  -> Running automated compliance checks on $ID..."
    
    # Send the PATCH request to verify and show the backend ABAC response
VERIFY_RES=$(curl -s -X PATCH \
    -H "Authorization: Bearer $TOKEN" \
    "$API_BASE_URL/system/verify/$ID")

echo "$VERIFY_RES" | jq

if echo "$VERIFY_RES" | jq -e '.abacDecision' > /dev/null; then
    echo "  -> [SUCCESS] $ID status updated to VERIFIED."
else
    echo "  -> [FAILED] Could not verify $ID."
fi

done

echo "Verification Job Complete."
