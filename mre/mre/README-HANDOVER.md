# Azure WAF — refactored to the repo's conventions

Repo: `ccoe-onecloud-azure-firewall-workload`

This folder mirrors the repo's paths exactly. Copy the three folders in, commit, run.

---

## What I read from your screenshots

| From | Finding | Consequence |
|---|---|---|
| `workload/versions.tf` | **azurerm pinned to `4.81.0`**, not v5 | My whole bundle assumed `>= 5.0`. Everything here is re-verified against 4.81. |
| `workload/versions.tf` | `provider "azurerm"` with `storage_use_azuread = true`, `features {}`, **no `subscription_id`** | No provider block and no `subscription_id` variable anywhere in my code. The subscription comes from the pipeline credentials. |
| `workload/versions.tf` | `required_providers` lists only `azurerm` and `time` | **No `random` provider.** Unique names derive deterministically from the subscription id instead, so you never have to touch Renovate-managed `versions.tf`. |
| `environments/sbx/bootstrap.tfbackend` | `rg-westeurope-tfbackend`, key `sbx.bootstrap.tfstate`, `use_azuread_auth = true` | Naming convention `rg-<location>-<purpose>` adopted. Backend already solved — nothing from me. |
| `data.tf`, `workload.tfvars` | both empty | Clean slate. No conventions to reverse-engineer, no conflicts. |

---

## Copy these in

```
infrastructure/workload/data.tf          <- replaces the empty file
infrastructure/workload/locals.tf        <- new
infrastructure/workload/main.tf          <- new
infrastructure/workload/variables.tf     <- new
infrastructure/workload/outputs.tf       <- new

infrastructure/modules/waf-policy-appgw/ <- new
infrastructure/modules/waf-policy-afd/   <- new

infrastructure/environments/sbx/workload.tfvars   <- replaces the empty file
```

**Do not touch `workload/versions.tf`.** It is correct and Renovate manages it.

## Delete from the repo root

These were mine and now duplicate or contradict the repo's structure:

```
00-bootstrap/  10-platform/  10-platform-sub/  20-modules/
30-workload/   40-exceptions/  pipelines/  sandbox.tfvars
RUNSHEET.md  PERSONAL-TENANT.md  DEVOPS_REQUEST.md
```

Keep `tests/` — it is layout-independent and still useful. Consider moving it to
`infrastructure/tests/`.

**`10-platform*` and `40-exceptions` are not lost — they belong in a different repo.** This
one is `...-firewall-workload`. Azure Policy definitions, the initiative and exemptions are
subscription or management-group scoped and are not workload resources. Ask where the
governance repo is before recreating them anywhere.

---

## Two bugs found and fixed during the refactor

**1. Front Door and Application Gateway use different field names for the same concepts.**
`match_variable` vs `variable_name`; `duration_minutes` (1 or 5) vs `duration`
("OneMin"/"FiveMins") plus `group_by`. The old code passed one set of rule lists to both
modules. Harmless while the lists are empty; it would have failed at the first tuning step.
Each platform now has its own variables.

**2. The DRS version asymmetry is real, and the provider proves it.**
On azurerm 4.81:

| | Documented `Microsoft_DefaultRuleSet` versions |
|---|---|
| `azurerm_web_application_firewall_policy` (App Gateway) | `2.1`, `2.2` |
| `azurerm_cdn_frontdoor_firewall_policy` (Front Door) | `1.1`, `2.0`, `2.1` |

So **2.2 on Front Door is not available on your pinned provider.** The module default of 2.1
was right, and this is now evidence rather than a PoC question. Design proposal §5.1 can be
updated: the Front Door baseline is DRS 2.1 while Application Gateway runs 2.2, and that is a
provider and platform constraint, not a choice.

## One asymmetry worth knowing before you promise an app team a fix

Exclusion `match_variable` values on 4.81:

- **Application Gateway** — `RequestArgKeys/Names/Values`, `RequestCookieKeys/Names/Values`, `RequestHeaderKeys/Names/Values`
- **Front Door** — the above *plus* `RequestBodyJsonArgNames`

A false positive on a **JSON body field** is tunable on Pattern A and may not be on Pattern B.
That is exactly the scenario in the worked exception example (`reporting-api`,
`queryExpression`), so it is not hypothetical.

## Verified present on 4.81

`resource_guid` on `azurerm_cdn_frontdoor_profile` (the `X-Azure-FDID` value) ·
`ip_restriction_default_action`, `service_tag`, `x_azure_fdid`, `x_fd_health_probe` on
`azurerm_linux_web_app` · `rate_limit_duration`, `rate_limit_threshold`,
`group_rate_limit_by` on the App Gateway WAF policy · `custom_rules` plural on App Gateway,
`custom_rule` singular on Front Door · CAPTCHA and JSChallenge on Front Door are **PREVIEW**.

---

## Running it

The pipeline does the work. Locally, to check a plan:

```bash
cd infrastructure/workload
terraform init -backend-config=../environments/sbx/workload.tfbackend
terraform plan -var-file=../environments/sbx/workload.tfvars
```

### First apply

`workload.tfvars` as shipped gives: resource group, Log Analytics, App Service origin, VNet
and subnet, Application Gateway WAF_v2 with its policy. **Front Door is off** — it bills for
every hour or partial hour the profile exists, so it is opt-in.

**Application Gateway takes 15–25 minutes.** That is normal.

### Then one change per run

| Run | Change | Produces |
|---|---|---|
| 1 | as shipped | Baseline. Bypass test **unlocked** — the first half of the evidence. |
| 2 | `lockdown_enabled = true` | Bypass test again. **The pair is the proof.** |
| 3 | `waf_mode = "Prevention"` | After tuning, with the exclusion from a real false positive |
| 4 | `enable_frontdoor = true` | Pattern A. Billable — turn it off afterwards. |

Never jump ahead. The before/after at each step is the result.

---

## Check before the first apply

- `vnet_address_space = "10.100.0.0/16"` — does it clash with anything in sbx? Nothing in the
  screenshots told me, so it is a guess. Change it if needed.
- Does sbx already have a VNet or a Log Analytics workspace to consume? If so, set
  `existing_vnet_name` / `log_analytics_workspace_name` and move them into `data.tf`.
- Is `rg-westeurope-waf` the right name? I inferred `rg-<location>-<purpose>` from
  `rg-westeurope-tfbackend`. If the standard differs, tell me rather than leaving two
  conventions in one repo.

## Still open

- Where does the governance layer live? Different repo.
- Is CI GitHub Actions or Azure Pipelines? If Actions, my `pipelines/*.yml` are the wrong
  syntax and should be deleted rather than adapted — the reusable workflow probably covers it.
- `terraform validate` has still never run on this code. The pipeline's validate step is the
  first real check; expect it to find something and send me the output.
