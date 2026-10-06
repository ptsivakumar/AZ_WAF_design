# 10-platform-sub — single-subscription variant

Use this layer instead of `10-platform/` when the PoC environment is **one subscription with no
management group**. That is the `ccoe-waf-sbx` situation.

**Environment as configured:** subscription `ccoe-waf-sbx`, existing resource group
`ccoe-waf-poc-rg`, `create_resource_group = false`. Values live in `../sandbox.tfvars`.

Everything else in the bundle (`20-modules`, `30-workload`, `40-exceptions`, `pipelines`, `tests`)
is unchanged — only the scope of the policy objects differs.

## What changes

| `10-platform/` (management group) | `10-platform-sub/` (subscription) |
|---|---|
| `azurerm_policy_definition` with `management_group_id` | same resource, argument omitted → subscription scope |
| `azurerm_management_group_policy_set_definition` | `azurerm_policy_set_definition` |
| `azurerm_management_group_policy_assignment` | `azurerm_subscription_policy_assignment` |
| Two subscriptions (platform / workload) | Two resource groups in one subscription |

Policy JSON is **not duplicated** — this layer reads `../10-platform/policies/*.json`.

## What is not exercised, and must be stated in the findings report

- Management-group-scoped assignment. In production the initiative is assigned at the Landing
  Zones management group and inherited by every subscription beneath it.
- Definition storage at the intermediate root. A definition stored in a subscription can only
  ever be assigned to that subscription — which is exactly why production stores them higher.
- Inheritance behaviour across subscriptions, and exemption scoping below an inherited assignment.

These are limitations of the environment, not of the design. Say so plainly rather than claiming
the guardrail model was validated end to end.

## Permissions

| Action | Role needed | Contributor can do it? |
|---|---|---|
| Resource groups, Log Analytics, App Gateway, Front Door, WAF policies | Contributor | **Yes** |
| Create policy definitions / initiative / assignment | Resource Policy Contributor | **No** |
| Create policy exemptions | Resource Policy Contributor **and** `exempt/Action` on the assignment | **No** |
| Role assignment for the remediation identity | RBAC Administrator or User Access Administrator | **No** |

Contributor's `NotActions` include `Microsoft.Authorization/*/Write` and
`Microsoft.Authorization/*/Delete`, which is why everything in the Authorization provider is
blocked. Verify what you actually hold before you plan anything:

```bash
az role assignment list --assignee <your-upn> \
  --scope /subscriptions/$(az account show --query id -o tsv) -o table
```

## Running it

Both policy switches default to **false**, so the first apply succeeds with Contributor alone.

```bash
# Stage 1 — today, with Contributor only
terraform init
terraform apply -var-file=../sandbox.tfvars
# creates: Log Analytics workspace inside ccoe-waf-poc-rg

# Stage 2 — once Resource Policy Contributor is granted
terraform apply -var-file=../sandbox.tfvars -var="enable_policy=true"

# Stage 3 — only if you also hold RBAC Administrator
terraform apply -var-file=../sandbox.tfvars \
  -var="enable_policy=true" -var="enable_remediation_role=true"
```

If you do not hold RBAC Administrator, leave stage 3 off and send the
`policy_assignment_principal_id` output to whoever does:

```bash
az role assignment create \
  --assignee-object-id $(terraform output -raw policy_assignment_principal_id) \
  --assignee-principal-type ServicePrincipal \
  --role Contributor \
  --scope /subscriptions/$(az account show --query id -o tsv)
```

Until that role assignment exists, `DeployIfNotExists` policies evaluate and report
non-compliance correctly but **cannot remediate**. `Audit` and `Deny` are unaffected.

## Audit to enforce

`-var="initiative_effect=Deny"` is the single switch. Run it only after the compliance snapshot
in audit mode has been captured as evidence — the before/after pair is the point of the test.
