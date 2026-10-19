# Azure WAF — module map and enforcement model

Design document for review. Azure, Application Gateway first.

Status key used throughout:

| | |
|---|---|
| **BUILT** | Exists, tested in `ccoe-waf-sbx` |
| **DESIGNED** | Approach agreed, not implemented |
| **OPEN** | Needs a decision or a fact we do not have |

---

## 1. How to read this

The work is broken into nine modules. Each one answers the same eight
questions, so a gap is visible rather than discovered during rollout:

1. **Guarantee** — what is true afterwards that was not true before
2. **Greenfield** — how a new application gets it without asking
3. **Brownfield** — discovery, migration, and what breaks
4. **Pipeline check** — what fails the plan
5. **Azure Policy** — what is audited, what is denied, and when
6. **Runtime check** — what catches the change both of those missed
7. **Evidence** — the test that proves it and the number that tracks it
8. **Owner** — platform, security, or application team

---

## 2. The coverage model

This is the most important page in the document. Every control has to answer
two questions: *when* is it checked, and *what does it reach*.

| | **Workloads using the platform module** | **Everything else** — other IaC, portal, other pipelines, legacy |
|---|---|---|
| **At deploy** | Pipeline validation — **BUILT** | Azure Policy deny — **DESIGNED** |
| **After deploy** | Scheduled `terraform plan` — **DESIGNED** | Azure Policy audit + Resource Graph + SIEM — **DESIGNED** |

Everything delivered so far sits in **one cell of four**. It is the right cell
to start with, because it is where new work enters. It is not the control.

Three consequences worth stating plainly:

**A control that exists only in the pipeline is advisory.** The pipeline sees
one repository. It cannot see the exclusion added in the portal at 2am during
an incident, or the gateway another team built last year.

**A check that only runs when someone deploys is lazy.** The exception expiry
we built fires on `terraform plan`. If a workload is untouched for six months,
the exception expires and nothing happens. A scheduled plan is what converts an
expiry date from a statement of intent into a control.

**Azure Policy is the only layer that reaches everything** — and it is the one
layer currently blocked, because Contributor cannot create policy objects.

### The rule that avoids a fight

> **Azure Policy may *deploy* only what Terraform does not own. Where Terraform
> owns the resource, Policy audits and never remediates.**

Without this, a DeployIfNotExists policy remediates a resource Terraform
manages, the next plan shows drift, Terraform reverts it, Policy remediates
again. Decide it once and it saves a lot of confusion later.

---

## 3. The enforcement ladder

No control jumps straight to blocking. Each module declares which rung it is on
and the date it moves to the next. The date is the part that matters — a
recommendation without one is a request, and at 100+ applications teams
rationally prioritise the thing with a deadline.

| Rung | What it means |
|---|---|
| **0 — Documented** | The specification exists. Teams not using the module can still comply. |
| **1 — Paved road** | The module makes it the default. Easier to comply than not. |
| **2 — Detected** | Audit policy. Teams see their own non-compliance, and so does their leadership. |
| **3 — Blocked for new** | Deny policy. Existing resources grandfathered by a **dated Azure Policy exemption**. |
| **4 — Blocked for all** | Exemptions expire. Nothing left to grandfather. |

### Grandfathering, done properly

Azure Policy exemptions carry a **built-in expiry date**. So rather than a soft
recommendation with no end:

1. Set the policy to **Deny**
2. Create an **exemption per existing non-compliant application**, each with an
   expiry and a justification
3. The exemption expiring is what moves that application from grandfathered to
   blocked

Azure then generates the list of exactly who is non-compliant and until when.
Nobody maintains it. It is also the same pattern as the WAF exclusion expiry —
one concept, two places, one thing for teams to learn.

---

## 4. Module map

| | Module | Depends on | Rung today | Status |
|---|---|---|---|---|
| 0 | Inventory and coverage baseline | — | — | OPEN |
| 1 | Telemetry | 0 | 1 | Partly BUILT (sbx) |
| 2 | **Origin lockdown** | 1 | 0 | BUILT in sbx, proven by test |
| 3 | WAF attached, Detection mode | 1 | 1 | BUILT in sbx |
| 4 | **Central rule definition and distribution** | 3 | 1 | BUILT for one repo |
| 5 | **Exception flow** | 4 | 1 | BUILT, deploy-time only |
| 6 | Change control — who can turn it off | 3 | 0 | DESIGNED |
| 7 | Coverage reporting | 0, 2, 3 | — | DESIGNED |
| 8 | Prevention mode | 3, 5 | 0 | Not started |

Front Door after Application Gateway. AKS parked until we know what it is.

---

## 5. Module 0 — inventory and coverage baseline

**Guarantee.** We know how many internet-facing applications exist, where they
are, and which are already covered. Nothing else can be planned without it.

**Why first.** At 100+ applications you cannot size the rollout, sequence
waves, or report progress without a list. It is also the answer to the request
to *clean up the list* before kick-offs.

**How.** Azure Resource Graph across the tenant:

- Application Gateways, their SKU, whether they have a public frontend IP,
  whether a WAF policy is attached
- Front Door profiles and their tier
- App Services and Function Apps with public access and no IP restrictions
- Which subscriptions and management groups they sit in

**Evidence.** A table with one row per application. The baseline that every
later percentage is measured against.

**Owner.** Platform. Read-only — needs Reader at tenant or MG scope, which is a
smaller ask than policy rights.

**Open.** Does an application inventory or CMDB already exist that this should
join to rather than duplicate?

---

## 6. Module 1 — telemetry

**Guarantee.** Every gateway, Front Door profile and origin sends diagnostics
to the central Log Analytics workspace.

**Why before lockdown.** Brownfield lockdown needs access logs to discover who
actually calls an origin. Without logs that discovery is guesswork, and every
later detection depends on the data existing.

**Greenfield.** The module wires diagnostics automatically. BUILT.

**Brownfield.** DeployIfNotExists policy. This is the safest DINE on the list —
diagnostic settings are rarely owned by a workload's own Terraform, so the
ownership rule in section 2 is not violated.

**Pipeline check.** Diagnostics present on gateway, Front Door and origin.
BUILT.

**Evidence.** Log volume per workload. A workload sending nothing is either
idle or not wired up, and both are worth knowing.

**Owner.** Platform.

---

## 7. Module 2 — origin lockdown

**Guarantee.** The application cannot be reached around the WAF.

This is the foundation. A WAF with an open origin is decoration, and that is
not an argument — it is evidenced. Before lockdown a SQL injection payload sent
directly to the origin returned 200. After, 403, while the legitimate path
through the gateway still returned 200.

Two numbers follow from this, and they are different: *behind a WAF* and *with
the bypass closed*. The first is always higher. Publishing only the first
overstates protection.

**Greenfield.** Lockdown on from day one. A new application has no existing
callers to break, so there is no reason to be gentle. Rung 3 — deny — can apply
to new applications immediately.

**Brownfield — this is the hard part and it will dominate the schedule.**

Turning on lockdown for a running application breaks every caller that is not
the gateway: partner integrations, on-prem systems, monitoring probes, the
batch job nobody documented. This cannot be done blind. Per application:

1. Enable access logs (module 1)
2. Observe real callers for two weeks
3. Enumerate them and confirm each with the application team
4. Apply the restriction
5. Re-run the five-request bypass test — before and after, both logs kept

At 100+ applications, with a two-week observation window each, this must run in
parallel waves. It is a programme, not a task.

**The SCM site.** `<app>.scm.azurewebsites.net` is a separate hostname with its
own access restrictions, reaching the same application. Locking only the main
site leaves a working route around the WAF. Any runbook that says "add an
access restriction" without naming both is incomplete. Found by test, now fixed
in the Terraform.

**Pipeline check.** `lockdown_enabled` must be true outside sandbox. DESIGNED.

**Azure Policy.** Audit App Services reachable without IP restrictions. Deny
for new; dated exemptions for existing. DESIGNED.

**Runtime check.** Access restrictions removed — Activity Log event, alert in
the SIEM.

**Evidence.** The before/after bypass test pair. Either log alone proves
nothing; the value is entirely in the pair.

**Owner.** Application team applies it, platform provides the runbook and the
discovery query.

---

## 8. Module 3 — WAF attached, Detection mode

**Guarantee.** Every internet-facing application has a WAF policy attached, in
at least Detection mode.

**Detection first, deliberately.** Prevention on an untuned policy breaks
applications and destroys the rollout's credibility in week one. Detection
produces the false-positive evidence that exclusions are later based on.

**Greenfield.** The module builds gateway, policy and association together.
BUILT.

**Brownfield.** Attach a policy in Detection to an existing gateway. Low risk —
it observes and logs without blocking.

**Pipeline check.** SKU must be `WAF_v2`. A policy that exists but is attached
to nothing protects nothing, so association is checked too. DESIGNED — neither
is implemented yet.

**Azure Policy.** Deny an Application Gateway with a public frontend and a
non-WAF SKU. Audit policies not associated with anything. Microsoft publishes
built-ins covering part of this — the exact definitions need verifying before
being relied on.

**Evidence.** Percentage of internet-facing applications with a policy
attached, from Resource Graph.

**Owner.** Platform.

---

## 9. Module 4 — central rule definition and distribution

The architecturally interesting one.

**Guarantee.** The mandatory rules reach every workload, and an application
team cannot remove them.

### Where the rules live

**Today:** `infrastructure/workload/central-rules.tf`, inside the CCoE repo,
protected by CODEOWNERS. An application team editing its own `tfvars` has no
way to add, reorder or delete a central rule. BUILT — and sufficient for the
pilot only.

**Target:** the rules move inside a **published, versioned Terraform module**:

```hcl
module "waf" {
  source  = "<registry>/munichre/waf-policy/azurerm"
  version = "1.3.0"
}
```

Application teams have their own repositories, so a file in ours cannot reach
them. The rules have to travel with the module.

**OPEN:** where the registry lives — Azure DevOps Artifacts, GitHub releases,
or a private Terraform registry.

### What cannot be shared

An Azure WAF policy cannot be shared across subscriptions or regions. An
Application Gateway policy must sit in the same subscription *and* region as
its gateway. There is no single policy covering the estate, and nobody should
promise one.

> Central definitions, federated enforcement.

### Priority bands

| Band | Owner | Purpose |
|---|---|---|
| 1–9 | Security | Emergency virtual patch |
| 10–39 | Security | Mandatory central rules |
| 40–69 | Security | Rate limits |
| 70–100 | Application team | Application-specific |

A rule outside its band fails the plan in about fifteen seconds. BUILT.

### The version-drift problem

A team pins v1.0. We publish v1.3 with a new mandatory rule. It never reaches
them, and nothing looks wrong from their side.

**The cheap fix: stamp the version as a tag at deploy.**

```hcl
tags = { waf-baseline-version = "1.3.0" }
```

One Resource Graph query then lists every WAF policy below the current
baseline. No policy aliases needed, no API calls, and it produces a coverage
number that can be published. DESIGNED.

### What needs verifying before this module is designed properly

**Does Azure Policy have aliases deep enough to inspect WAF custom rules and
exclusions?**

```bash
az provider show --namespace Microsoft.Network \
  --expand "resourceTypes/aliases" \
  --query "resourceTypes[?resourceType=='ApplicationGatewayWebApplicationFirewallPolicies'].aliases[].name" -o tsv
```

- **If yes:** policy can audit "this policy is missing central rule X" and
  "this policy has a blanket exclusion" estate-wide. The control is real for
  everyone.
- **If no:** policy can only check coarse properties, and rule *content* can be
  guaranteed only through the module plus drift detection. For teams not using
  the module the honest answer becomes "we detect, we do not prevent".

Twenty minutes of work; it determines half this module.

**A rule set version change resets exclusions** to the new set's defaults,
quietly re-breaking every application that was tuned. Exclusions are held in
code so they can be re-applied — but the reconciliation step is DESIGNED, not
built.

**Owner.** Security owns the rules. Platform owns the module and its release.

---

## 10. Module 5 — exception flow

**Guarantee.** An exception to the WAF is scoped, justified, owned and
temporary — and the pipeline enforces all four before any human looks at it.

### What is built

Nine checks, each tested, each failing the plan in about fifteen seconds with a
readable message and no Azure resource touched:

| Check | |
|---|---|
| Application rule outside band 70–100 | BUILT |
| Duplicate rule priorities | BUILT |
| Exclusion with no rule group — blanket | BUILT |
| Justification under 30 characters | BUILT |
| `requested_by` / `risk_owner` not named people | BUILT |
| Ticket reference malformed | BUILT |
| Expiry malformed, passed, or over 90 days | BUILT |
| `match_variable` not valid for that platform | BUILT |
| Front Door exclusion with no rule IDs | BUILT |

### Two names, not one

`requested_by` is the engineer. `risk_owner` is the application owner who
accepts the residual risk. Security sets the guardrails; the business owner
accepts what is left inside them.

This only works if application owners can genuinely say no to their own
delivery pressure. If that is not real in practice, it is a fig leaf and
splitting approval by risk tier is the more honest design. **OPEN — for Markus.**

### Scope, and why the two platforms differ

Application Gateway scopes an exclusion with `excluded_rule_set` → `rule_group`
and can narrow to named rule IDs.

Front Door has no such field — scope comes from *where the exclusion sits*. And
azurerm documents that an override block containing no rule blocks **disables
every rule in the group**. A group-scoped exclusion written the obvious way
would switch off far more than it excluded. The code therefore requires Front
Door exclusions to name the rule IDs that actually fired, which avoids the trap
and is more precise anyway.

Found in the provider documentation, not in production.

### The register is not a register

`terraform output waf_exceptions_in_force` is a **projection of the code**, not
a document anyone maintains. It cannot drift from reality because it is
reality, read out differently. Delete an exclusion and it leaves the view the
same second.

The **decision** — risk acceptance, approval, business justification — belongs
in the organisation's existing exception process, which per our discussion
should be the **firewall rule exception process**. Mirror its fields and
vocabulary so an auditor sees one process with two flavours. The ticket number
is the join. We reference; we do not duplicate.

**Action: obtain the firewall exception form.** One conversation. It tells us
the field names and the expiry periods the organisation already accepts,
instead of my asserting 90 days.

### Two gaps, stated plainly

**The ticket is format-checked, not verified.** `SEC-9999` passes whether or
not such a record exists. At pilot scale the ticket buys traceability, not
control. Closing it means calling the exception system's API from the pipeline
and refusing to merge unless the record exists, is approved, and carries the
same expiry as the code. Scoped work, not done.

**Expiry only fires when someone deploys.** If a workload is untouched for six
months the exception expires silently. **A scheduled `terraform plan` per
workload is what fixes this** — one job, catching expired exceptions and portal
drift together. Of everything in this document, this is the cheapest thing with
the largest effect.

**Owner.** Application team raises; nobody approves at pilot scale; pipeline
validates.

---

## 11. Module 6 — change control

**Guarantee.** An application team cannot turn the WAF off.

This is the module that makes the others real, and it is currently missing.

If an application team holds Contributor on its subscription, it can open the
portal and set the policy to Detection, delete an exclusion, or detach the
policy entirely. The pipeline will not see it. Azure Policy will mark it
non-compliant *after the fact*. Neither prevents it.

**How.** A deny assignment or custom role removing from application teams:

- `Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/write`
- `Microsoft.Network/applicationGateways/write`
- App Service access-restriction write actions

leaving those actions to the pipeline identity only.

**Runtime check.** Until that exists: alert on any WAF policy write by a
principal other than the pipeline's. Activity Log, straightforward KQL. This is
the layer that answers *who did it and when*, which is the question actually
asked after an incident.

Politically the hardest module and technically one of the easiest. Without it,
the honest description of everything above is *advisory*.

**Owner.** Platform and security jointly. Needs a decision above this team.

---

## 12. Module 7 — coverage reporting

**Guarantee.** Progress is measurable and the measure is honest.

| Metric | Source |
|---|---|
| % internet-facing applications behind a WAF | Resource Graph |
| % with the bypass closed | Resource Graph + policy compliance |
| % on the current baseline version | `waf-baseline-version` tag |
| Exceptions in force / expired / expiring in 30 days | Scheduled plan output |

The first two are different numbers and the second is always lower. Reporting
only the first overstates protection — which the sandbox test demonstrates.

**Owner.** Platform.

---

## 13. Module 8 — Prevention mode

**Guarantee.** The WAF blocks rather than observes.

Last, deliberately. Requires a tuning window per application, with exclusions
derived from real Detection-mode false positives rather than guesses.

Entry criteria per application: WAF attached, lockdown closed, 30 days in
Detection, false positives tuned, application team informed of the switch date.

**Evidence.** The same five-request test, where the attack through the gateway
flips from 307 to 403.

**Owner.** Application team, with security sign-off per wave.

---

## 14. Decisions needed

| | Decision | Options | Lean |
|---|---|---|---|
| D1 | Who approves an exception | Self-service / tiered by risk / security approves all | Self-service at pilot, revisit at scale |
| D2 | Where the decision record lives | Mirror the firewall exception process / build our own / none | Mirror it |
| D3 | Risk owner | Application owner / security / split by tier | Application owner — if it is real |
| D4 | Module registry | ADO Artifacts / GitHub releases / private TF registry | OPEN |
| D5 | Enforcement dates per module | — | OPEN — the dates matter more than the ladder |
| D6 | Who gets policy rights, at what scope | — | OPEN — blocks everything in the Azure Policy column |

---

## 15. To find out

| | Why it matters |
|---|---|
| **Azure Policy alias depth** for WAF custom rules and exclusions | Decides whether rule content can be enforced estate-wide or only detected |
| **The firewall exception form** | Gives us field names and expiry norms the organisation already accepts |
| **Management group shape** and who can assign policy there | Everything in the Azure Policy column depends on it |
| **What "container / AKS" means here** — AGIC, Front Door to AKS, or something else | Lockdown works completely differently (private link / NSG, not IP allow). May not be the same module at all. |
| **Application inventory / CMDB** — does one exist? | Module 0 should join to it, not duplicate it |

---

## 16. What is true today

Proven in `ccoe-waf-sbx`:

- Origin lockdown works and is verifiable by test, not assertion
- The SCM site is a second door and must be locked separately
- Application Gateway supports DRS 2.2; Front Door only to 2.1 on azurerm 4.81
- Front Door supports `RequestBodyJsonArgNames` exclusions; Application Gateway
  does not — so a JSON-body false positive may be untunable on Pattern B
- The exception gate blocks nine distinct failure cases at plan time
- A Terraform-built App Service, plan and workspace deploy through the pipeline

Not yet true:

- Nothing is enforced outside this repository
- Nothing is re-checked after deployment
- No Azure Policy exists
- Prevention mode has never run
- Front Door has never been deployed
- Scale is untested — one workload, one subscription
