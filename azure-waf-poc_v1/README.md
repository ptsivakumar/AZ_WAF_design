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
10-platform/      Log Analytics, policy definitions, initiative, assignment. Management group scope.
10-platform-sub/  The same, scoped to ONE subscription.                      Use INSTEAD of 10-platform.
20-modules/       Reusable WAF policy modules. Not applied directly.
30-workload/      Test app, Application Gateway, Front Door, lockdown.       Workload subscription / RG.
40-exceptions/    Policy exemptions and their written records.
pipelines/        Azure DevOps pipeline and the exclusion reconciliation.
tests/            Permission check, bypass test, traffic generation, exception validation.
```

Apply in that order. `10-platform` and `30-workload` both consume `20-modules`.

## Which platform layer do I use?

| Environment | Layer |
|---|---|
| A test **management group** with two subscriptions under it | `10-platform/` |
| **One subscription**, no management group — `ccoe-waf-sbx` | `10-platform-sub/` ← **this one** |

Pick one. Never both — they create policy objects with the same names at different scopes.
`10-platform-sub/README.md` lists exactly what the subscription-scoped run does **not** prove,
and that list belongs in the findings report.

## Before you start

```bash
az login
az account set --subscription "ccoe-waf-sbx"
terraform -version     # >= 1.9 recommended

# Run this FIRST. It tells you what your role actually permits,
# by attempting each operation rather than reading the role name.
./tests/check-permissions.sh
```

## The only file you edit: `sandbox.tfvars`

One value is missing from it — the subscription GUID:

```bash
az account show --query id -o tsv
```

Paste it into `subscription_id` and you are done. Also confirm `location` matches the
region `ccoe-waf-poc-rg` is actually in:

```bash
az group show -n ccoe-waf-poc-rg --query location -o tsv
```

Then pass that one file to every layer:

```bash
cd 10-platform-sub && terraform init && terraform apply -var-file=../sandbox.tfvars
cd ../30-workload  && terraform init && terraform apply -var-file=../sandbox.tfvars
```

**`create_resource_group = false`** is the important setting. `ccoe-waf-poc-rg` already
exists, and Terraform does not adopt resources it did not create — without this it fails with
*"A resource with this ID already exists"*. With it false, Terraform binds to the group through
a data source and creates everything inside it.

Everything that changes during the PoC — `enable_policy`, `waf_mode`, `lockdown_enabled`,
`afd_ruleset_version`, `initiative_effect` — is passed with `-var` on the command line rather
than stored in the file. Each flip is then a deliberate, logged action with a before and after,
which is the point of the test.

**Contributor is not enough for the policy layer.** The built-in Contributor role's `NotActions`
include `Microsoft.Authorization/*/Write` and `Microsoft.Authorization/*/Delete`, which blocks
policy definitions, assignments, exemptions and role assignments. You also need **Resource Policy
Contributor** (`36243c78-bf99-498c-9df9-86d9f8d28608`). Everything else in this bundle —
Application Gateway, Front Door, WAF policies, origin lockdown, logging, the bypass tests — works
with Contributor alone, which is why `enable_policy` defaults to `false` in `10-platform-sub`.

`10-platform/` (the management-group variant) is the exception — it keeps its own
`mgmt_group_id` and `platform_sub_id` variables and is not driven by `sandbox.tfvars`. Leave it
alone unless a test management group appears.

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
