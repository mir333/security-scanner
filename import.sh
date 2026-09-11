#!/bin/sh
# Push a scanner report into DefectDojo via /api/v2/import-scan/.
# Expects: DD_URL DD_ADMIN_USER DD_ADMIN_PASSWORD DD_PRODUCT_NAME DD_PRODUCT_TYPE_NAME
#          DD_MINIMUM_SEVERITY SCAN_TYPE REPORT_FILE ENGAGEMENT_NAME
set -eu

[ -s "$REPORT_FILE" ] || { echo "import: report $REPORT_FILE missing or empty" >&2; exit 1; }

echo "import: fetching API token from $DD_URL"
token=$(curl -sSf -X POST "$DD_URL/api/v2/api-token-auth/" \
  --data-urlencode "username=$DD_ADMIN_USER" \
  --data-urlencode "password=$DD_ADMIN_PASSWORD" \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$token" ] || { echo "import: could not obtain API token" >&2; exit 1; }

echo "import: uploading '$SCAN_TYPE' ($REPORT_FILE) -> product '$DD_PRODUCT_NAME' / engagement '$ENGAGEMENT_NAME'"
# Same product+engagement on every run: DefectDojo dedups findings and closes ones that disappeared.
resp=$(curl -sS -w '\n%{http_code}' -X POST "$DD_URL/api/v2/import-scan/" \
  -H "Authorization: Token $token" \
  -F "scan_type=$SCAN_TYPE" \
  -F "file=@$REPORT_FILE" \
  -F "product_type_name=$DD_PRODUCT_TYPE_NAME" \
  -F "product_name=$DD_PRODUCT_NAME" \
  -F "engagement_name=$ENGAGEMENT_NAME" \
  -F "auto_create_context=true" \
  -F "minimum_severity=$DD_MINIMUM_SEVERITY" \
  -F "active=true" \
  -F "verified=false" \
  -F "close_old_findings=true" \
  -F "scan_date=$(date +%F)")
code=$(printf '%s' "$resp" | tail -n1)
body=$(printf '%s' "$resp" | sed '$d')

if [ "$code" != "201" ]; then
  echo "import: FAILED (HTTP $code): $body" >&2
  exit 1
fi
echo "import: OK (HTTP 201) test_id=$(printf '%s' "$body" | sed -n 's/.*"test_id":\([0-9]*\).*/\1/p')"
