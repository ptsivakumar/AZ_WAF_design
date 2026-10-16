#!/usr/bin/env bash
# =============================================================================
# Synthetic traffic for Detection-mode analysis — runbook step 4.3
# Generates a mix of clean traffic, obvious attacks, and one request that
# is LEGITIMATE but looks malicious — the planted false positive that
# step 4.4 then tunes with a narrow exclusion.
#
# Usage: ./traffic-gen.sh <target-url> [iterations]
# =============================================================================
set -uo pipefail
URL="${1:?Target URL, e.g. https://wafpoc-ep.z01.azurefd.net}"
N="${2:-50}"

echo "Generating $N iterations against $URL"
echo "Allow 5-10 minutes for logs to appear in Log Analytics."

for i in $(seq 1 "$N"); do
  # --- clean traffic -------------------------------------------------------
  curl -s -o /dev/null "${URL}/"
  curl -s -o /dev/null "${URL}/about"

  # --- obvious attacks: should match managed rules -------------------------
  curl -s -o /dev/null "${URL}/?id=1%27%20OR%20%271%27=%271"          # SQLi
  curl -s -o /dev/null "${URL}/?q=<script>alert(1)</script>"           # XSS
  curl -s -o /dev/null "${URL}/../../etc/passwd"                       # traversal
  curl -s -o /dev/null -H "User-Agent: sqlmap/1.7" "${URL}/"           # central rule band 10-39

  # --- THE PLANTED FALSE POSITIVE -----------------------------------------
  # A legitimate reporting API that sends SQL-like filter syntax in a JSON
  # field. This is the exact scenario in the design proposal, section 10.2.
  # It should match SQLI rule 942xxx. Step 4.4 adds a narrow exclusion on
  # RequestBodyJsonArgNames / queryExpression and nothing else.
  curl -s -o /dev/null -X POST "${URL}/v1/reports/search" \
    -H 'Content-Type: application/json' \
    -d '{"queryExpression":"status = '"'"'active'"'"' OR amount > 1000"}'

  [ $((i % 10)) -eq 0 ] && echo "  ... $i"
done
echo "Done. Query with tests/kql/ queries."
