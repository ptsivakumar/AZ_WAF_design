#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# check-permissions.sh — run this FIRST, before any terraform.
#
# Answers one question: what can I actually do in this subscription today?
# Every check is empirical — it attempts the operation and cleans up after
# itself — because a role assignment list tells you what you were granted,
# not what survives the NotActions.
#
# Usage:  ./check-permissions.sh
# Needs:  az CLI, already logged in (az login)
# Creates nothing permanent. The probe policy definition is deleted again.
# ---------------------------------------------------------------------------
set -uo pipefail

PROBE="wafpoc-permission-probe"
PASS=0
FAIL=0

ok()   { echo "  PASS   $1"; PASS=$((PASS+1)); }
no()   { echo "  FAIL   $1"; FAIL=$((FAIL+1)); }
info() { echo "         $1"; }

echo
echo "=========================================================="
echo " Azure WAF PoC — sandbox permission check"
echo "=========================================================="

# --- 0. identity and subscription -----------------------------------------
SUB_ID=$(az account show --query id -o tsv 2>/dev/null)
SUB_NAME=$(az account show --query name -o tsv 2>/dev/null)
UPN=$(az account show --query user.name -o tsv 2>/dev/null)

if [[ -z "${SUB_ID}" ]]; then
  echo "Not logged in. Run: az login"
  exit 1
fi

echo
echo "Subscription : ${SUB_NAME}"
echo "ID           : ${SUB_ID}"
echo "Signed in as : ${UPN}"
SCOPE="/subscriptions/${SUB_ID}"

# --- 1. what roles do I hold ----------------------------------------------
echo
echo "--- 1. Role assignments on this subscription (including inherited)"
az role assignment list \
  --assignee "${UPN}" \
  --scope "${SCOPE}" \
  --include-inherited \
  --query "[].{role:roleDefinitionName, scope:scope}" -o table 2>/dev/null \
  || info "Could not list role assignments. You may lack read on Microsoft.Authorization — that is itself a finding."

# --- 2. resource providers -------------------------------------------------
# A fresh subscription often has these unregistered. Registration needs
# Contributor and can take several minutes. Do it now, not mid-apply.
echo
echo "--- 2. Resource provider registration"
for NS in Microsoft.Network Microsoft.Cdn Microsoft.Web Microsoft.OperationalInsights \
          Microsoft.Insights Microsoft.Storage Microsoft.ServiceNetworking; do
  STATE=$(az provider show -n "${NS}" --query registrationState -o tsv 2>/dev/null)
  case "${STATE}" in
    Registered)   ok "${NS}" ;;
    Registering)  info "WAIT   ${NS} — registering, check again in a few minutes" ;;
    *)            no "${NS} is '${STATE:-unknown}' — run: az provider register --namespace ${NS}" ;;
  esac
done
info "Microsoft.ServiceNetworking is only needed if Application Gateway for Containers is in scope."

# --- 3. can I create a policy definition ----------------------------------
echo
echo "--- 3. Microsoft.Authorization — the Contributor blind spot"
RULE='{"if":{"field":"type","equals":"Microsoft.Network/applicationGateways"},"then":{"effect":"audit"}}'

if az policy definition create \
      --name "${PROBE}" \
      --display-name "WAF PoC permission probe - safe to delete" \
      --description "Created by check-permissions.sh. Deleted immediately. Not assigned to anything." \
      --rules "${RULE}" \
      --mode Indexed \
      --subscription "${SUB_ID}" >/dev/null 2>&1; then
  ok "policyDefinitions/write — you can create policy definitions"
  az policy definition delete --name "${PROBE}" --subscription "${SUB_ID}" >/dev/null 2>&1 \
    && info "probe definition deleted" \
    || info "WARNING: probe definition '${PROBE}' could not be deleted. Remove it by hand."
  POLICY_OK=1
else
  no "policyDefinitions/write — BLOCKED"
  info "Expected with Contributor alone: its NotActions include"
  info "Microsoft.Authorization/*/Write. You need Resource Policy Contributor."
  POLICY_OK=0
fi

# --- 4. can I create a role assignment ------------------------------------
# Not probed by creating one — a stray role assignment is not a safe probe.
# Checked by reading the role definitions you can see and reporting honestly.
echo
echo "--- 4. Role assignment creation (needed for DeployIfNotExists remediation)"
if az role assignment list --assignee "${UPN}" --scope "${SCOPE}" --include-inherited \
     --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='User Access Administrator' || roleDefinitionName=='Role Based Access Control Administrator'] | length(@)" \
     -o tsv 2>/dev/null | grep -qv '^0$'; then
  ok "You hold a role that can create role assignments"
  RBAC_OK=1
else
  no "No Owner / User Access Administrator / RBAC Administrator found"
  info "Set enable_remediation_role = false and hand the"
  info "policy_assignment_principal_id output to someone who has it."
  RBAC_OK=0
fi

# --- 5. quota ---------------------------------------------------------------
echo
echo "--- 5. Public IP quota in the target region (Application Gateway needs one)"
az network list-usages --location "${AZ_LOCATION:-westeurope}" \
  --query "[?contains(name.value,'PublicIPAddresses')].{resource:name.localizedValue, used:currentValue, limit:limit}" \
  -o table 2>/dev/null || info "Could not read quota."

# --- summary ----------------------------------------------------------------
echo
echo "=========================================================="
echo " What you can do today"
echo "=========================================================="
echo
echo "  Always available with Contributor:"
echo "    10-platform-sub   with enable_policy=false   (RG + Log Analytics)"
echo "    30-workload                                  (app, App Gateway, Front Door, WAF policies)"
echo "    tests/bypass-test.sh, traffic-gen.sh, the KQL queries"
echo "    The DRS 2.2 on Front Door question — resolved by one apply"
echo
if [[ "${POLICY_OK}" == "1" ]]; then
  echo "  Policy objects: AVAILABLE — run with -var=\"enable_policy=true\""
else
  echo "  Policy objects: BLOCKED — request Resource Policy Contributor"
  echo "                  role id 36243c78-bf99-498c-9df9-86d9f8d28608"
fi
if [[ "${RBAC_OK}" == "1" ]]; then
  echo "  Remediation role assignment: AVAILABLE"
else
  echo "  Remediation role assignment: BLOCKED — ask someone to create the one assignment"
fi
echo
echo "  ${PASS} checks passed, ${FAIL} failed."
echo
echo "Record this output in the PoC evidence log. It is the baseline"
echo "that explains which objectives could and could not be tested."
echo
