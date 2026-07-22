#!/bin/bash

# Configuration
KEYCLOAK_URL="http://192.168.30.10:8080/realms/cyber-audit-portal/protocol/openid-connect/token"
API_BASE_URL="http://localhost:3050/api"
CLIENT_ID="audit-validator-client"
CLIENT_SECRET="${AUDIT_VALIDATOR_CLIENT_SECRET}"

if [ -z "$CLIENT_SECRET" ]; then
    echo "Missing AUDIT_VALIDATOR_CLIENT_SECRET environment variable."
    exit 1
fi
echo "Starting Automated Evidence Validation Job (Shell)..."

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

# Fetch all evidence and use jq to filter for SUBMITTED items, returning just their IDs
SUBMITTED_IDS=$(curl -s -H "Authorization: Bearer $TOKEN" "$API_BASE_URL/pending/report" | jq -r '.[] | select(.status=="SUBMITTED") | .id')

if [ -z "$SUBMITTED_IDS" ]; then
    echo "No SUBMITTED evidence found. Exiting."
    exit 0
fi

# Process and validate each submitted evidence item
for ID in $SUBMITTED_IDS; do
    echo "  -> Running automated controls validation on evidence $ID..."
    
    # Send the PATCH request to validate and show the backend ABAC response
VERIFY_RES=$(curl -s -X PATCH \
    -H "Authorization: Bearer $TOKEN" \
    "$API_BASE_URL/system/verify/$ID")

echo "$VERIFY_RES" | jq

if echo "$VERIFY_RES" | jq -e '.abacDecision' > /dev/null; then
    echo "  -> [SUCCESS] $ID status updated to VALIDATED."
else
    echo "  -> [FAILED] Could not validate evidence $ID."
fi

done

echo "Evidence Validation Job Complete."
