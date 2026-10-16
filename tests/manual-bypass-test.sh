#!/usr/bin/env bash
# =============================================================================
# manual-bypass-test.sh — origin lockdown evidence, by hand, no Terraform.
#
# For the stack already in waf-sbx:
#   waf-sbx-appgw  (WAF_v2, policy attached)
#        -> origin-app-example (App Service, currently reachable directly)
#
# RUN IT TWICE. The pair is the evidence; either run alone proves nothing.
#   Run 1  BEFORE adding access restrictions   -> bypass WORKS   (the problem)
#   Run 2  AFTER  adding access restrictions   -> bypass FAILS   (the control)
#
# Usage:  ./manual-bypass-test.sh <appgw-public-ip-or-hostname> [origin-hostname]
# Example: ./manual-bypass-test.sh 20.50.1.23 origin-app-example.azurewebsites.net
# =============================================================================
set -uo pipefail

GW="${1:?Application Gateway public IP or DNS name}"
ORIGIN="${2:-origin-app-example.azurewebsites.net}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="bypass-manual-${STAMP}.log"

code() { curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$@" 2>/dev/null || echo "ERR"; }
row()  { printf '%-52s %-10s %s\n' "$1" "$2" "$3" | tee -a "$OUT"; }

{
  echo "Origin lockdown — manual bypass test"
  echo "Run at:   $STAMP"
  echo "Gateway:  $GW"
  echo "Origin:   $ORIGIN"
  echo "Operator: ${USER:-unknown}"
  echo
  printf '%-52s %-10s %s\n' "TEST" "HTTP" "MEANING"
  printf '%-52s %-10s %s\n' "----" "----" "-------"
} | tee "$OUT"

# --- 1. clean traffic the legitimate way -----------------------------------
C=$(code "http://${GW}/")
row "1. Clean request VIA the gateway" "$C" "$([ "$C" = "200" ] && echo 'OK — the good path works' || echo 'Check the gateway/backend health')"

# --- 2. clean traffic straight to the origin -------------------------------
# THE WHOLE POINT. If this succeeds, the WAF is optional.
C=$(code "https://${ORIGIN}/")
row "2. Clean request DIRECT to origin" "$C" "$([ "$C" = "403" ] && echo 'LOCKED — bypass refused' || echo 'OPEN — the WAF can be bypassed')"

# --- 3. attack via the gateway ---------------------------------------------
# In Detection mode this returns 200 and is logged. In Prevention it is blocked.
C=$(code "http://${GW}/?id=1%27%20OR%20%271%27=%271")
row "3. SQL injection VIA the gateway" "$C" "$([ "$C" = "403" ] && echo 'BLOCKED by WAF (Prevention)' || echo '200 = Detection mode, check the logs for a match')"

# --- 4. the same attack straight past the WAF ------------------------------
# This is the slide. An attack that the WAF would catch, reaching the
# application untouched, because nothing forces traffic through the WAF.
C=$(code "https://${ORIGIN}/?id=1%27%20OR%20%271%27=%271")
row "4. SAME attack DIRECT to origin" "$C" "$([ "$C" = "403" ] && echo 'Refused — WAF cannot be bypassed' || echo 'REACHED THE APP — WAF bypassed entirely')"

# --- 5. XSS straight to the origin -----------------------------------------
C=$(code "https://${ORIGIN}/?q=%3Cscript%3Ealert(1)%3C/script%3E")
row "5. XSS DIRECT to origin" "$C" "$([ "$C" = "403" ] && echo 'Refused' || echo 'Reached the app')"

{
  echo
  echo "Saved to $OUT"
  echo
  echo "READING THIS:"
  echo "  Run 1 (before lockdown): tests 2, 4, 5 should all return 200."
  echo "    That is the finding — the WAF is in the path only for people who"
  echo "    choose to use it. An attacker does not."
  echo
  echo "  Run 2 (after lockdown):  tests 2, 4, 5 should all return 403,"
  echo "    while test 1 still returns 200. The control is proven."
  echo
  echo "Keep BOTH logs. One without the other proves nothing."
} | tee -a "$OUT"
