#!/usr/bin/env bash
# =============================================================================
# Origin lockdown bypass test — PoC objective 2, runbook step 4.1
#
# This is the most important test in the PoC. Run it TWICE:
#   1. with lockdown_enabled = false  -> establishes the baseline (bypass WORKS)
#   2. with lockdown_enabled = true   -> the control is proven (bypass FAILS)
# A single run proves nothing. The pair is the evidence.
#
# Usage:  ./bypass-test.sh <frontdoor-host> <origin-host> <our-fdid>
# =============================================================================
set -uo pipefail

FD_HOST="${1:?Front Door hostname, e.g. wafpoc-ep-xxxx.z01.azurefd.net}"
ORIGIN="${2:?Origin hostname, e.g. wafpoc-app-xxxxx.azurewebsites.net}"
OUR_FDID="${3:?Our Front Door profile GUID (X-Azure-FDID)}"
FOREIGN_FDID="00000000-0000-0000-0000-000000000001"

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="bypass-test-${STAMP}.log"

code() { curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$@"; }

line() { printf '%-58s %-6s %s\n' "$1" "$2" "$3" | tee -a "$OUT"; }

{
  echo "Origin lockdown bypass test"
  echo "Run at:        $STAMP"
  echo "Front Door:    $FD_HOST"
  echo "Origin:        $ORIGIN"
  echo "Our FDID:      $OUR_FDID"
  echo "----------------------------------------------------------------------"
  printf '%-58s %-6s %s\n' "TEST" "CODE" "EXPECTED ONCE LOCKED DOWN"
} | tee "$OUT"

# 1. Legitimate path — must ALWAYS work. If this breaks, lockdown is misconfigured.
C=$(code "https://${FD_HOST}/")
line "1. Through Front Door (legitimate)" "$C" "200 — must keep working"

# 2. Direct to origin, no headers — the actual bypass.
C=$(code "https://${ORIGIN}/")
line "2. Direct to origin, no headers" "$C" "403 — the control"

# 3. Direct to origin spoofing OUR FDID from an unapproved network.
#    Service tag restricts source to Front Door IPs, so this should still fail.
C=$(code -H "X-Azure-FDID: ${OUR_FDID}" "https://${ORIGIN}/")
line "3. Direct + our FDID header spoofed" "$C" "403 — service tag blocks source"

# 4. Direct to origin with a FOREIGN FDID — proves the header value is checked,
#    not merely its presence. This is the test that catches the common mistake
#    of allowing the AzureFrontDoor.Backend service tag with no header check.
C=$(code -H "X-Azure-FDID: ${FOREIGN_FDID}" "https://${ORIGIN}/")
line "4. Direct + FOREIGN FDID header" "$C" "403 — not our profile"

# 5. SCM / Kudu endpoint — frequently forgotten and publicly reachable.
C=$(code "https://${ORIGIN%%.azurewebsites.net}.scm.azurewebsites.net/")
line "5. SCM (Kudu) site" "$C" "403 — set scm_use_main_ip_restriction"

echo "----------------------------------------------------------------------" | tee -a "$OUT"
echo "Saved to $OUT — attach to the findings report as objective 2 evidence." | tee -a "$OUT"
echo "" | tee -a "$OUT"
echo "READ THE RESULT HONESTLY: if test 2, 3, 4 or 5 returns 200 with lockdown" | tee -a "$OUT"
echo "enabled, the control does NOT hold. That is a valid and valuable finding," | tee -a "$OUT"
echo "not a failed PoC. Record it and change the design." | tee -a "$OUT"
