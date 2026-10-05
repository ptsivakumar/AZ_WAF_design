# Azure WAF — Proof of Concept code bundle

Supports `Azure_WAF_PoC_Implementation_Runbook.docx`. Every step number below maps to a step in
that runbook.

## Verified against

| Item | Version / source | Date |
|---|---|---|
| Terraform AzureRM provider | **5.8.0** (latest at time of writing) | Oct 2026 |
| `azurerm_application_load_balancer_security_policy` | requires provider **>= 4.38.0** | Oct 2026 |
| Resource and argument names | HashiCorp provider docs, tag v5.8.0 | Oct 2026 |

## Two corrections that will bite you if you copy older examples

1. **`azurerm_policy_set_definition` no longer accepts `management_group_id` in provider v5.**
   Use **`azurerm_management_group_policy_set_definition`** instead. Plain
   `azurerm_policy_definition` *does* still take `management_group_id` — the asymmetry is real.

2. **Front Door WAF policy and DRS 2.2.** The provider documents only `1.1`, `2.0`, `2.1` for
   `Microsoft_DefaultRuleSet` on `azurerm_cdn_frontdoor_firewall_policy`, while Microsoft Learn
   states DRS 2.2 is current for Front Door Premium. The provider does **not** validate the
   string — it passes plan and is sent verbatim to the API, so a bad value fails at apply, not
   at plan. Application Gateway's `azurerm_web_application_firewall_policy` **does** document
   `2.2`. This discrepancy is deliberately a PoC test (runbook step 4.2), not an assumption.
   `var.managed_ruleset_version` exists so the fallback to `2.1` is a variable change, not a
   rewrite.

## Layout and order of execution

```
00-bootstrap/     Resource group + storage account for Terraform state.      Run once, local state.
10-platform/      Log Analytics, policy definitions, initiative, assignment. Platform subscription.
20-modules/       Reusable WAF policy modules. Not applied directly.
30-workload/      Test app, Application Gateway, Front Door, lockdown.       Workload subscription.
pipelines/        Azure DevOps pipeline and the exclusion reconciliation.
tests/            Bypass test and traffic generation.
```

Apply in that order. `10-platform` and `30-workload` both consume `20-modules`.

## Before you start

```bash
az login
az account set --subscription "<platform subscription id>"
terraform -version     # >= 1.9 recommended
```

Set these environment variables, or create `terraform.tfvars` in each layer:

```
TF_VAR_mgmt_group_id        = "<test management group id>"
TF_VAR_platform_sub_id      = "<platform subscription id>"
TF_VAR_workload_sub_id      = "<workload subscription id>"
TF_VAR_location             = "westeurope"
TF_VAR_prefix               = "wafpoc"
```

## Policy aliases — read this before applying 10-platform

The custom policy definitions in `10-platform/policies/` reference Azure Policy **aliases**.
Aliases change between API versions and **could not be verified offline**. Before applying,
confirm each one exists in your tenant:

```bash
az provider show --namespace Microsoft.Network \
  --expand "resourceTypes/aliases" \
  --query "resourceTypes[?resourceType=='applicationGateways'].aliases[].name" -o tsv

az provider show --namespace Microsoft.Cdn \
  --expand "resourceTypes/aliases" \
  --query "resourceTypes[?resourceType=='profiles'].aliases[].name" -o tsv

az provider show --namespace Microsoft.Web \
  --expand "resourceTypes/aliases" \
  --query "resourceTypes[?resourceType=='sites'].aliases[].name" -o tsv
```

Each JSON file names the aliases it uses in a `_comment` field. Fix any that do not appear in
the output above before `terraform apply`. A wrong alias does not error — the policy simply
never matches anything, which is far worse.
