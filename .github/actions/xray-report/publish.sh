set -euo pipefail

if [[ -z "$APP_ID" || -z "$APP_PRIVATE_KEY" ]]; then
  echo '::error title=Missing GitHub App credentials::Configure TOY_CHECK_APP_ID and TOY_CHECK_APP_PRIVATE_KEY in the job environment.'
  exit 1
fi

base64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

key_file="$(mktemp)"
comment_response_file="$(mktemp)"
trap 'rm -f "$key_file" "$comment_response_file"' EXIT
printf '%s' "$APP_PRIVATE_KEY" > "$key_file"
chmod 600 "$key_file"

# GitHub App JWTs use RS256, may live for at most ten minutes, and should
# backdate iat slightly to tolerate clock drift.
now="$(date +%s)"
header="$(printf '%s' '{"alg":"RS256","typ":"JWT"}' | base64url)"
payload="$(jq -nc \
  --arg iss "$APP_ID" \
  --argjson iat "$((now - 60))" \
  --argjson exp "$((now + 540))" \
  '{iat: $iat, exp: $exp, iss: $iss}' | base64url)"
unsigned_jwt="${header}.${payload}"
signature="$(printf '%s' "$unsigned_jwt" | openssl dgst -sha256 -sign "$key_file" | base64url)"
app_jwt="${unsigned_jwt}.${signature}"

installation="$(curl --fail-with-body --silent --show-error \
  -H 'Accept: application/vnd.github+json' \
  -H "Authorization: Bearer $app_jwt" \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  "$API_URL/repos/$REPOSITORY/installation")"
installation_id="$(jq -er '.id' <<<"$installation")"

# pull_requests:write is required here in practice for comments on a PR;
# checks:write permits publishing the Check Run.
token_request="$(jq -nc \
  --argjson repository_id "$REPOSITORY_ID" \
  '{repository_ids: [$repository_id], permissions: {checks: "write", pull_requests: "write"}}')"
installation_token="$(curl --fail-with-body --silent --show-error \
  -X POST \
  -H 'Accept: application/vnd.github+json' \
  -H "Authorization: Bearer $app_jwt" \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  -H 'Content-Type: application/json' \
  --data "$token_request" \
  "$API_URL/app/installations/$installation_id/access_tokens" \
  | jq -er '.token')"

# Count only severity cells in the Vulnerable Components table. This excludes
# scanner log messages and unrelated text after the table.
declare -A findings=(
  [Critical]=0
  [High]=0
  [Medium]=0
  [Low]=0
  [Unknown]=0
)
if [[ -f "$REPORT_PATH" ]]; then
  while IFS=$'\t' read -r severity count; do
    findings["$severity"]="$count"
  done < <(
    awk -F '│' '
      /^Vulnerable Components[[:space:]]*$/ { awaiting_table = 1; next }
      awaiting_table && /^┌/ { in_table = 1; awaiting_table = 0; next }
      in_table && /^└/ { in_table = 0; next }
      in_table {
        severity = $3
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", severity)
        if (severity == "Critical" || severity == "High" || severity == "Medium" || severity == "Low" || severity == "Unknown") {
          counts[severity]++
        }
      }
      END {
        for (severity in counts) print severity "\t" counts[severity]
      }
    ' "$REPORT_PATH"
  )
fi

critical="${findings[Critical]}"
high="${findings[High]}"
medium="${findings[Medium]}"
low="${findings[Low]}"
unknown="${findings[Unknown]}"

if (( critical > 0 )); then
  conclusion='failure'
  title="🚨 Critical $PRODUCT_NAME security findings"
  status_message="❌ $critical Critical finding(s) require remediation."
elif (( high > 0 )); then
  conclusion='action_required'
  title="⚠️ High $PRODUCT_NAME security findings need attention"
  status_message="⚠️ $high High finding(s) need attention."
else
  conclusion='success'
  title="✅ $PRODUCT_NAME security scan passed"
  status_message='✅ No Critical or High findings.'
fi

statistics="$(printf '| Severity | Events |\n| --- | ---: |\n| 🚨 Critical | %s |\n| 🔴 High | %s |\n| 🟠 Medium | %s |\n| 🟡 Low | %s |\n| ⚪ Unknown | %s |' \
  "$critical" "$high" "$medium" "$low" "$unknown")"
summary="$(printf '## %s\n\n%s\n\n%s' "$CHECK_NAME" "$status_message" "$statistics")"

comment_payload="$(jq -nc --arg body "$summary" '{body: $body}')"
if ! comment_http_status="$(curl --silent --show-error \
  --output "$comment_response_file" \
  --write-out '%{http_code}' \
  -X POST \
  -H 'Accept: application/vnd.github+json' \
  -H "Authorization: Bearer $installation_token" \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  -H 'Content-Type: application/json' \
  --data "$comment_payload" \
  "$API_URL/repos/$REPOSITORY/issues/$PR_NUMBER/comments")"; then
  echo '::error title=PR comment request failed::curl could not reach the GitHub API.'
  exit 1
fi

if [[ ! "$comment_http_status" =~ ^2[0-9][0-9]$ ]]; then
  echo "::error title=PR comment request failed::GitHub returned HTTP $comment_http_status."
  echo 'GitHub API response:'
  jq . "$comment_response_file" || sed 's/^/  /' "$comment_response_file"
  exit 1
fi
comment_url="$(jq -er '.html_url' "$comment_response_file")"
jq '{id, html_url}' "$comment_response_file"

check_run="$(jq -nc \
  --arg name "$CHECK_NAME" \
  --arg head_sha "$PR_HEAD_SHA" \
  --arg conclusion "$conclusion" \
  --arg title "$title" \
  --arg summary "$summary" \
  '{name: $name, head_sha: $head_sha, status: "completed", conclusion: $conclusion, output: {title: $title, summary: $summary}}')"

check_response="$(curl --fail-with-body --silent --show-error \
  -X POST \
  -H 'Accept: application/vnd.github+json' \
  -H "Authorization: Bearer $installation_token" \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  -H 'Content-Type: application/json' \
  --data "$check_run" \
  "$API_URL/repos/$REPOSITORY/check-runs")"
check_run_url="$(jq -er '.html_url' <<<"$check_response")"
jq '{id, name, status, conclusion, html_url}' <<<"$check_response"

{
  echo "conclusion=$conclusion"
  echo "critical-count=$critical"
  echo "high-count=$high"
  echo "medium-count=$medium"
  echo "low-count=$low"
  echo "unknown-count=$unknown"
  echo "comment-url=$comment_url"
  echo "check-run-url=$check_run_url"
} >> "$GITHUB_OUTPUT"

# Publish both artifacts before applying the blocking policy.
if (( critical > 0 )) && [[ "$FAIL_ON_CRITICAL" == 'true' ]]; then
  exit 1
fi
