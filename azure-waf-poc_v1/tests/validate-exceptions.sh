#!/usr/bin/env bash
# =============================================================================
# Exception process validation — V1 to V6 of the exception design.
#
# This tests the GOVERNANCE, not the WAF. It answers: can an application team
# waive a control on its own? The answer must be no, and "we wrote it in a
# document" is not evidence.
#
# Usage: ./validate-exceptions.sh <assignment-id> <target-resource-id>
# Run V1 while authenticated AS AN APPLICATION TEAM IDENTITY, not as yourself.
# =============================================================================
set -uo pipefail

ASSIGNMENT="${1:?policy assignment id}"
TARGET="${2:?resource id to exempt}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="exception-validation-${STAMP}.log"

say() { printf '%s\n' "$*" | tee -a "$OUT"; }

say "Exception process validation — $STAMP"
say "Assignment: $ASSIGNMENT"
say "Target:     $TARGET"
say "Signed in as: $(az account show --query user.name -o tsv 2>/dev/null)"
say "======================================================================"

# --- V1 : an application team identity MUST NOT be able to create one -------
say ""
say "V1 — application team attempts to create an exemption (MUST FAIL)"
if az policy exemption create \
      --name "v1-should-fail" \
      --policy-assignment "$ASSIGNMENT" \
      --exemption-category Waiver \
      --scope "$TARGET" \
      --expires-on "2027-01-01T00:00:00Z" 2>>"$OUT"; then
  say "  RESULT: CREATED — ** CONTROL FAILED **"
  say "  The RBAC separation is not in place. An application team can waive a"
  say "  control on its own. Record this as a finding and fix before Phase 3."
  az policy exemption delete --name "v1-should-fail" --scope "$TARGET" 2>/dev/null
else
  say "  RESULT: REFUSED — control holds."
  say "  Creating an exemption needs policyExemptions/write on the resource AND"
  say "  exempt/Action on the assignment. Confirm WHICH one refused you."
fi

# --- V2 : security creates one, resource becomes Exempt --------------------
say ""
say "V2 — after security creates the exemption, state must be Exempt"
say "  Run from 40-exceptions:  terraform apply"
say "  Then:"
say "    az policy state list --resource '$TARGET' \\"
say "      --query \"value[].{policy:policyDefinitionName, state:complianceState}\" -o table"
say "  EXPECT: Exempt — not Compliant, and not NonCompliant."
say "  Compliant would mean the control is silently not evaluated at all."

# --- V3 : scoping ----------------------------------------------------------
say ""
say "V3 — the exemption covers ONE control, not the initiative"
say "  Confirm the exempted control shows Exempt AND the other twelve still"
say "  evaluate normally. Run tests/arg/04-blanket-exemptions.kql — it must"
say "  return zero rows."

# --- V4 : expiry -----------------------------------------------------------
say ""
say "V4 — expiry behaviour"
say "  Set expiryDate to tomorrow in the record, apply, wait, then re-check."
say "  EXPECT: the exemption object still EXISTS but is no longer honoured,"
say "  and the resource returns to its real compliance state."
say "  Azure does not warn you. Reporting is the only control - which is why"
say "  tests/arg/02-exception-debt.kql must run monthly."

# --- V5 : the register -----------------------------------------------------
say ""
say "V5 — the register reconciles"
say "  Compare:  terraform output -json active_exceptions"
say "  against:  tests/arg/01-exception-register.kql"
say "  They must agree exactly. A row in Azure that is not in the repository"
say "  was created by hand."

# --- V6 : out-of-process detection -----------------------------------------
say ""
say "V6 — nothing was created outside the process"
say "  Run tests/arg/03-unmanaged-exemptions.kql. EXPECT zero rows."
say "  Any row is an exemption with no exceptionId in its metadata, i.e."
say "  created by hand. If V1 passed, this should be impossible."

say ""
say "======================================================================"
say "Saved to $OUT"
