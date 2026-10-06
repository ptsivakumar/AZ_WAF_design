#!/usr/bin/env bash
# =============================================================================
# Exclusion drift reconciliation — PoC objective 4, runbook step 4.8
#
# WHY THIS EXISTS
#   Microsoft: changing the managed rule set version in a WAF policy RESETS
#   rule states, rule actions and rule-level exclusions to the new set's
#   defaults. Custom rules and policy settings survive.
#   The rule set version is owned centrally; exclusions are owned by the
#   application team. So a central upgrade silently destroys another team's
#   tested configuration - and the policy still reports compliant.
#
#   This script compares what Terraform INTENDED against what is actually on
#   the policy in Azure, and fails the pipeline on any difference.
#
# Usage: ./reconcile-exclusions.sh <resource-group> <waf-policy-name> <intended.json>
#        where intended.json is `terraform output -json intended_exclusions`
# =============================================================================
set -euo pipefail

RG="${1:?resource group}"
POLICY="${2:?WAF policy name}"
INTENDED_FILE="${3:?path to intended exclusions JSON}"

echo "Reconciling exclusions on ${POLICY} in ${RG}"

ACTUAL=$(az network application-gateway waf-policy show \
  --resource-group "$RG" --name "$POLICY" \
  --query "managedRules.exclusions" -o json)

# Normalise both sides: sort, drop nulls, compare canonical JSON.
norm() {
  python3 -c '
import json,sys
d = json.load(sys.stdin) or []
out = sorted(
    (
        (i.get("matchVariable") or i.get("match_variable") or "").lower(),
        (i.get("selector") or "").lower(),
        (i.get("selectorMatchOperator") or i.get("selector_match_operator") or "").lower(),
    )
    for i in d
)
print(json.dumps(out, indent=2))'
}

A=$(echo "$ACTUAL"            | norm)
I=$(cat "$INTENDED_FILE"      | norm)

if [ "$A" == "$I" ]; then
  echo "PASS — applied exclusions match the module output."
  exit 0
fi

echo "FAIL — exclusion drift detected."
echo ""
echo "INTENDED (from the Terraform module):"
echo "$I"
echo ""
echo "ACTUAL (on the policy in Azure):"
echo "$A"
echo ""
echo "Most likely cause: the managed rule set version was changed, which resets"
echo "rule-level exclusions to the new set's defaults. Re-run terraform apply to"
echo "re-establish them, then re-run this check."
exit 1
