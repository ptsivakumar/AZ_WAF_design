# Azure WAF — reference design and Terraform

A working reference for putting a Web Application Firewall in front of Azure web
applications, with the two ingress patterns, the controls that make a WAF worth having, and
the tests that prove it.

Written for `azurerm` **4.81.0**. Resource names and arguments were verified against that
version's documentation, not assumed.

---

## The idea in one paragraph

Putting a WAF in front of an application is easy and, on its own, achieves close to nothing.
The security value comes from also **closing the route that goes around it**. An application
whose origin is still reachable directly has a WAF that an attacker simply ignores. Most of
this repository is about that second half.

---

## Two ingress patterns

| | Pattern A — Front Door Premium | Pattern B — Application Gateway WAF_v2 |
|---|---|---|
| Scope | Global | Regional |
| WAF policy location | Same subscription as the profile | **Same subscription AND same region as the gateway** |
| Managed rule set | DRS 2.1 (see below) | DRS 2.2 |
| CAPTCHA / JS challenge | Available (preview on 4.81) | Not available |
| Origin lockdown | `AzureFrontDoor.Backend` service tag **plus** `X-Azure-FDID` header | Allow the gateway's public IP |

That second row is the constraint that drives everything. A WAF policy cannot be shared across
regions or subscriptions, so no single central policy can cover an estate — the operating
model has to be federated. This is a platform constraint, not a design preference.

### The DRS version asymmetry is real

On azurerm 4.81:

| Resource | Documented `Microsoft_DefaultRuleSet` versions |
|---|---|
| `azurerm_web_application_firewall_policy` (App Gateway) | `2.1`, `2.2` |
| `azurerm_cdn_frontdoor_firewall_policy` (Front Door) | `1.1`, `2.0`, `2.1` |

So the Front Door baseline is 2.1 while Application Gateway runs 2.2. The module defaults
reflect that.

### Exclusions differ too

Application Gateway accepts `RequestArg*`, `RequestCookie*` and `RequestHeader*` selectors.
Front Door accepts those **plus `RequestBodyJsonArgNames`**. A false positive on a JSON body
field is therefore tunable on Pattern A and may not be on Pattern B — worth knowing before
promising an application team a fix.

---

## Layout

```
infrastructure/
├── workload/                 the Terraform root — what to build
│   ├── versions.tf           provider version and configuration
│   ├── data.tf               what already exists and is consumed
│   ├── locals.tf             naming and tags
│   ├── main.tf               the resources
│   ├── variables.tf          every knob, with defaults
│   └── outputs.tf            values the tests need afterwards
├── modules/
│   ├── waf-policy-appgw/     Application Gateway WAF policy
│   └── waf-policy-afd/       Front Door WAF policy
└── environments/
    └── sbx/
        ├── workload.tfvars            settings for one environment
        └── workload.tfbackend.example remote state config

tests/                        the evidence, which is the point
```

One root module, one tfvars per environment. Adding `dev` means adding
`environments/dev/workload.tfvars`, never copying the code — which is what stops environments
drifting apart.

---

## Priority bands

Custom rules are divided into reserved ranges so central and application rules cannot collide.
The module enforces this with a `precondition`, so a misplaced rule fails the plan rather than
being discovered in production.

| Band | Owner | Purpose |
|---|---|---|
| 1–9 | Security | Emergency virtual patch |
| 10–39 | Security | Mandatory central rules |
| 40–69 | Security | Rate limits |
| 70–100 | Application team | Application-specific, security approved |

---

## Using it

```bash
az login
az account set --subscription "<your subscription>"

cd infrastructure/workload
terraform init -backend-config=../environments/sbx/workload.tfbackend
terraform plan  -var-file=../environments/sbx/workload.tfvars
terraform apply -var-file=../environments/sbx/workload.tfvars
```

Both ingress patterns are behind toggles, because **Front Door Premium and Application Gateway
bill by the hour whether used or not**:

```hcl
enable_appgw     = false
enable_frontdoor = false
```

Start with one.

### Change one thing per run

The before-and-after at each step is the result. Skipping ahead loses it.

| Run | Change | Produces |
|---|---|---|
| 1 | as shipped | Baseline. Bypass test **unlocked**. |
| 2 | `lockdown_enabled = true` | Bypass test again — **the pair is the proof** |
| 3 | `waf_mode = "Prevention"` | After tuning, with an exclusion from a real false positive |
| 4 | `enable_frontdoor = true` | Pattern A. Billable — turn it off afterwards. |

---

## The tests matter more than the Terraform

| Script | Proves |
|---|---|
| `tests/bypass-test.sh` | The origin cannot be reached around the WAF. **Run twice** — unlocked, then locked. |
| `tests/manual-bypass-test.sh` | The same, against a hand-built stack. No Terraform needed. |
| `tests/traffic-gen.sh` | Generates clean traffic, attacks, and one deliberately planted false positive |
| `tests/check-permissions.sh` | What your identity can actually do — it attempts each operation rather than reading role names |
| `tests/kql/` | What matched, what would block, block rate, policy tampering |

The bypass test run twice is the single most valuable output. A clean run with lockdown on
proves nothing unless you also have the run that shows it was open before.

---

## Things that cost time if you learn them the hard way

**Terraform does not adopt resources it did not create.** Point it at an existing resource
group or gateway and it fails with *"A resource with this ID already exists"*. Use
`create_resource_group = false` and the existing-resource variables to consume rather than
create.

**Origin lockdown lives on the App Service**, inside `site_config.ip_restriction`. There is no
standalone resource for it, so Terraform must own the web app or it cannot manage the control.

**A WAF policy emits no logs.** Diagnostic settings belong on the Application Gateway or the
Front Door profile, not on the policy — the policy is configuration, not a service.

**A Front Door WAF policy does nothing until it is bound to a domain** through a security
policy. A policy that exists but is unassociated protects nothing.

**An Application Gateway v2 needs a dedicated subnet**, and if that subnet has an NSG it must
allow inbound TCP 65200–65535 from the `GatewayManager` service tag. Otherwise the deployment
fails after about twenty minutes with an error that does not say why.

**Managed rule set upgrades reset exclusions.** Keep exclusions in code and reconcile them in
the pipeline, or a version bump quietly re-breaks every application you tuned.

---

## Not included

Azure Policy guardrails — definitions, initiative, assignment, exemptions — belong at
subscription or management-group scope and are not workload resources. They sit in a separate
governance repository.

---

## Status

Verified against the azurerm 4.81.0 documentation. Not yet exercised by `terraform validate`
in this repository — treat the first plan as the first real check.
