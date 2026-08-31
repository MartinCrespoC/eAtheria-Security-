#!/bin/bash
set -e

# ============================================================
# AETHERIA Security Scan — GitHub Action Entrypoint
# ============================================================

API_URL="${AETHERIA_API_URL:-https://app.aetheria.io}"
SCAN_TYPES_CSV="${SCAN_TYPES:-sast,sca}"
FAIL_ON="${FAIL_ON:-critical}"
COMMENT="${COMMENT_ON_PR:-true}"
FIX_PR="${CREATE_FIX_PR:-false}"
PDF_REPORT="${PDF_REPORT:-true}"

# Parse scan types
IFS=',' read -ra SCAN_ARRAY <<< "$SCAN_TYPES_CSV"
SCAN_JSON=$(printf '"%s",' "${SCAN_ARRAY[@]}" | sed 's/,$//')

# Get repo info from GitHub context
REPO="${GITHUB_REPOSITORY}"
BRANCH="${GITHUB_HEAD_REF:-${GITHUB_REF_NAME:-main}}"
COMMIT="${GITHUB_SHA}"
PR_NUMBER="${PR_NUMBER:-}"

# Detect PR number from event
if [ -f "$GITHUB_EVENT_PATH" ]; then
  PR_NUMBER=$(jq -r '.pull_request.number // empty' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")
  PR_TITLE=$(jq -r '.pull_request.title // empty' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")
  PR_BASE=$(jq -r '.pull_request.base.ref // empty' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")
fi

echo "🛡️  AETHERIA Security Scan"
echo "   Repository: $REPO"
echo "   Branch:     $BRANCH"
echo "   Commit:     ${COMMIT:0:7}"
echo "   Scan types: $SCAN_TYPES_CSV"
echo ""

# ---- 1. Package source code ----
echo "📦 Packaging source code..."
ZIP_FILE=$(mktemp /tmp/aetheria-src-XXXXXX.zip)
B64_FILE=$(mktemp /tmp/aetheria-b64-XXXXXX.txt)
PAYLOAD_FILE=$(mktemp /tmp/aetheria-payload-XXXXXX.json)
trap 'rm -f "$ZIP_FILE" "$B64_FILE" "$PAYLOAD_FILE"' EXIT

# Zip the working tree, excluding VCS / dependency / build directories.
# (These folders are handled by SCA via OSV, not SAST.)
zip -rq "$ZIP_FILE" . \
  -x "*.git/*" "*node_modules/*" "*dist/*" "*build/*" "*out/*" \
     "*vendor/*" "*vendors/*" "*__pycache__/*" "*.venv/*" "*venv/*" \
     "*site-packages/*" "*target/*" "*.next/*" "*coverage/*" \
     "*.nyc_output/*" "*.cache/*" "*.parcel-cache/*" "*.gradle/*" \
     "*.m2/*" "*Pods/*" "*bower_components/*" "*.terraform/*" \
     "*pkg/*" "*bin/*" "*obj/*" 2>/dev/null || true

# base64 encode (single line). -w0 is GNU; fall back for other platforms.
base64 -w0 "$ZIP_FILE" > "$B64_FILE" 2>/dev/null || base64 "$ZIP_FILE" | tr -d '\n' > "$B64_FILE"
ZIP_SIZE=$(wc -c < "$ZIP_FILE" | tr -d ' ')
echo "   Source packaged: ${ZIP_SIZE} bytes (zip)"

# ---- 2. Trigger scan ----
# Build the JSON payload with jq so the large base64 string is handled safely.
jq -n \
  --arg repository "$REPO" \
  --arg branch "$BRANCH" \
  --arg commit "$COMMIT" \
  --rawfile code "$B64_FILE" \
  --argjson scanTypes "[${SCAN_JSON}]" \
  '{repository: $repository, branch: $branch, commit: $commit, scanTypes: $scanTypes, code: ($code | gsub("\\s+";""))}' > "$PAYLOAD_FILE"

# Attach PR context if available
if [ -n "$PR_NUMBER" ]; then
  jq --argjson num "$PR_NUMBER" --arg title "$PR_TITLE" --arg base "$PR_BASE" \
    '.pullRequest = {number: $num, title: $title, baseBranch: $base}' \
    "$PAYLOAD_FILE" > "${PAYLOAD_FILE}.tmp" && mv "${PAYLOAD_FILE}.tmp" "$PAYLOAD_FILE"
fi

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/api/v1/scan" \
  -H "Authorization: Bearer ${AETHERIA_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @"$PAYLOAD_FILE")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" != "202" ]; then
  echo "❌ Failed to start scan (HTTP $HTTP_CODE):"
  echo "$BODY" | jq . 2>/dev/null || echo "$BODY"
  exit 1
fi

SCAN_ID=$(echo "$BODY" | jq -r '.id')
echo "✅ Scan started: $SCAN_ID"
echo ""

# ---- 2. Poll for results ----
echo "⏳ Waiting for results..."
MAX_WAIT=300  # 5 minutes
ELAPSED=0
INTERVAL=10

while [ $ELAPSED -lt $MAX_WAIT ]; do
  sleep $INTERVAL
  ELAPSED=$((ELAPSED + INTERVAL))

  RESULT=$(curl -s -X GET "${API_URL}/api/v1/scan/${SCAN_ID}" \
    -H "Authorization: Bearer ${AETHERIA_API_KEY}")

  STATUS=$(echo "$RESULT" | jq -r '.status')

  if [ "$STATUS" = "COMPLETED" ] || [ "$STATUS" = "FAILED" ]; then
    break
  fi

  echo "   Status: $STATUS (${ELAPSED}s elapsed)"
done

if [ "$STATUS" = "FAILED" ]; then
  echo "❌ Scan failed"
  echo "$RESULT" | jq '.error // .message // empty' 2>/dev/null
  exit 1
fi

if [ "$STATUS" != "COMPLETED" ]; then
  echo "⏰ Scan timed out after ${MAX_WAIT}s (status: $STATUS)"
  echo "   Check results at: ${API_URL}/api/v1/scan/${SCAN_ID}"
  exit 1
fi

# ---- 3. Parse results ----
TOTAL=$(echo "$RESULT" | jq '.summary.total')
CRITICAL=$(echo "$RESULT" | jq '.summary.critical')
HIGH=$(echo "$RESULT" | jq '.summary.high')
MEDIUM=$(echo "$RESULT" | jq '.summary.medium')
LOW=$(echo "$RESULT" | jq '.summary.low')

echo ""
echo "📊 Scan Results"
echo "   Total issues:  $TOTAL"
echo "   🔴 Critical:   $CRITICAL"
echo "   🟠 High:       $HIGH"
echo "   🟡 Medium:     $MEDIUM"
echo "   🔵 Low:        $LOW"
echo ""

# Set outputs
echo "scan-id=$SCAN_ID" >> "$GITHUB_OUTPUT"
echo "total-issues=$TOTAL" >> "$GITHUB_OUTPUT"
echo "critical-count=$CRITICAL" >> "$GITHUB_OUTPUT"
echo "high-count=$HIGH" >> "$GITHUB_OUTPUT"
echo "status=$STATUS" >> "$GITHUB_OUTPUT"

# ---- 4. Post PR comment ----
if [ "$COMMENT" = "true" ] && [ -n "$PR_NUMBER" ] && [ -n "$GITHUB_TOKEN" ]; then
  echo "💬 Posting results to PR #$PR_NUMBER..."

  VULNS_TABLE=""
  VULN_COUNT=$(echo "$RESULT" | jq '.vulnerabilities | length')

  if [ "$VULN_COUNT" -gt 0 ]; then
    VULNS_TABLE="| Severity | Title | File | Line |\n|----------|-------|------|------|\n"
    for i in $(seq 0 $((VULN_COUNT - 1))); do
      V_SEV=$(echo "$RESULT" | jq -r ".vulnerabilities[$i].severity")
      V_TITLE=$(echo "$RESULT" | jq -r ".vulnerabilities[$i].title")
      V_FILE=$(echo "$RESULT" | jq -r ".vulnerabilities[$i].file // \"—\"")
      V_LINE=$(echo "$RESULT" | jq -r ".vulnerabilities[$i].line // \"—\"")
      VULNS_TABLE="${VULNS_TABLE}| ${V_SEV} | ${V_TITLE} | \`${V_FILE}\` | ${V_LINE} |\n"
    done
  fi

  COMMENT_BODY="## 🛡️ AETHERIA Security Scan\n\n"
  COMMENT_BODY+="| Metric | Count |\n|--------|-------|\n"
  COMMENT_BODY+="| 🔴 Critical | ${CRITICAL} |\n"
  COMMENT_BODY+="| 🟠 High | ${HIGH} |\n"
  COMMENT_BODY+="| 🟡 Medium | ${MEDIUM} |\n"
  COMMENT_BODY+="| 🔵 Low | ${LOW} |\n"
  COMMENT_BODY+="| **Total** | **${TOTAL}** |\n\n"

  if [ "$VULN_COUNT" -gt 0 ]; then
    COMMENT_BODY+="### Vulnerabilities Found\n\n${VULNS_TABLE}\n"
  fi

  COMMENT_BODY+="---\n*Powered by [AETHERIA Security](${API_URL})*"

  # Escape for JSON
  ESCAPED_BODY=$(echo -e "$COMMENT_BODY" | jq -Rs .)

  curl -s -X POST \
    "https://api.github.com/repos/${REPO}/issues/${PR_NUMBER}/comments" \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"body\": ${ESCAPED_BODY}}" > /dev/null

  echo "✅ PR comment posted"
fi

# ---- 5. Download PDF report ----
if [ "$PDF_REPORT" = "true" ] && [ "$STATUS" = "COMPLETED" ]; then
  REPORT_FILE="aetheria-security-report.pdf"
  curl -s -X GET "${API_URL}/api/v1/scan/${SCAN_ID}/report?format=pdf" \
    -H "Authorization: Bearer ${AETHERIA_API_KEY}" \
    -o "$REPORT_FILE"

  if head -c4 "$REPORT_FILE" 2>/dev/null | grep -q "%PDF"; then
    echo "📄 PDF report downloaded: $REPORT_FILE ($(wc -c < "$REPORT_FILE" | tr -d ' ') bytes)"
    echo "report-path=$REPORT_FILE" >> "$GITHUB_OUTPUT"
  else
    echo "⚠️  PDF report not available"
    rm -f "$REPORT_FILE"
  fi
fi

# ---- 6. Create fix PR (if enabled and fixes available) ----
if [ "$FIX_PR" = "true" ] && [ -n "$GITHUB_TOKEN" ]; then
  FIX_FILES=$(echo "$RESULT" | jq -r '[.vulnerabilities[] | select(.fix != null and .file != null) | .file] | unique | .[]' 2>/dev/null)

  if [ -n "$FIX_FILES" ]; then
    echo "🔧 Generating AI fixes with AETHERIA..."

    FILES_PAYLOAD="[]"
    while IFS= read -r f; do
      [ -f "$f" ] || continue
      VULNS_FOR_FILE=$(echo "$RESULT" | jq --arg f "$f" '[.vulnerabilities[] | select(.file == $f and .fix != null) | {title, lineStart: .line, description, fix}]')
      FILES_PAYLOAD=$(echo "$FILES_PAYLOAD" | jq --arg path "$f" --rawfile code "$f" --argjson vulns "$VULNS_FOR_FILE" \
        '. + [{path: $path, code: $code, vulnerabilities: $vulns}]')
    done <<< "$FIX_FILES"

    FIX_BRANCH="aetheria/security-fixes-${COMMIT:0:7}"
    FIX_RESPONSE=$(curl -s -X POST "${API_URL}/api/v1/fix-pr" \
      -H "Authorization: Bearer ${AETHERIA_API_KEY}" \
      -H "Content-Type: application/json" \
      -d "$(jq -n --argjson files "$FILES_PAYLOAD" --arg branch "$FIX_BRANCH" '{files: $files, branchName: $branch}')")

    PATCH_COUNT=$(echo "$FIX_RESPONSE" | jq '.totalFiles // 0')

    if [ "$PATCH_COUNT" -gt 0 ]; then
      echo "   $PATCH_COUNT files patched — creating PR..."

      git config user.name "aetheria-security[bot]"
      git config user.email "security-bot@aetheria.ikharoz.me"
      git checkout -b "$FIX_BRANCH"

      CHANGES_SUMMARY=""
      for i in $(seq 0 $((PATCH_COUNT - 1))); do
        P_PATH=$(echo "$FIX_RESPONSE" | jq -r ".patches[$i].path")
        echo "$FIX_RESPONSE" | jq -r ".patches[$i].fixedCode" > "$P_PATH"
        git add "$P_PATH"
        P_CHANGES=$(echo "$FIX_RESPONSE" | jq -r ".patches[$i].changes[]?" | sed 's/^/- /')
        CHANGES_SUMMARY="${CHANGES_SUMMARY}### \`${P_PATH}\`\n${P_CHANGES}\n\n"
      done

      COMMIT_MSG=$(echo "$FIX_RESPONSE" | jq -r '.commitMessage')
      git commit -q -m "$COMMIT_MSG"
      git push -f origin "$FIX_BRANCH"

      PR_BODY="## 🛡️ AETHERIA Security — Fixes automáticos con IA\n\n$(echo -e "$CHANGES_SUMMARY")---\n📄 Reporte detallado: artefacto \`aetheria-security-report\` de este workflow run.\n\n*Generado por [AETHERIA Security](${API_URL})*"

      PR_RESPONSE=$(curl -s -X POST "https://api.github.com/repos/${REPO}/pulls" \
        -H "Authorization: token ${GITHUB_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$(jq -n \
          --arg title "fix(security): AETHERIA auto-fixes (${PATCH_COUNT} files)" \
          --arg head "$FIX_BRANCH" --arg base "$BRANCH" --arg body "$PR_BODY" \
          '{title: $title, head: $head, base: $base, body: $body}')")

      PR_URL=$(echo "$PR_RESPONSE" | jq -r '.html_url // empty')
      if [ -n "$PR_URL" ]; then
        echo "✅ Fix PR created: $PR_URL"
        echo "fix-pr-url=$PR_URL" >> "$GITHUB_OUTPUT"
      else
        echo "⚠️  Could not create fix PR: $(echo "$PR_RESPONSE" | jq -r '.message // .errors[0].message // "unknown"')"
      fi
    else
      echo "ℹ️  No fix patches generated"
    fi
  fi
fi

# ---- 6. Fail if threshold exceeded ----
SHOULD_FAIL=false

case "$FAIL_ON" in
  critical)
    [ "$CRITICAL" -gt 0 ] && SHOULD_FAIL=true
    ;;
  high)
    [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ] && SHOULD_FAIL=true
    ;;
  medium)
    [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ] || [ "$MEDIUM" -gt 0 ] && SHOULD_FAIL=true
    ;;
  low)
    [ "$TOTAL" -gt 0 ] && SHOULD_FAIL=true
    ;;
  none)
    SHOULD_FAIL=false
    ;;
esac

if [ "$SHOULD_FAIL" = "true" ]; then
  echo "❌ Security gate FAILED — found issues at or above '${FAIL_ON}' severity"
  exit 1
else
  echo "✅ Security gate PASSED"
fi
