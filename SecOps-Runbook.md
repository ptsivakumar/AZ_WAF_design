# WAF baseline — operations runbook

For the people who own the baseline, not the people who consume it.

Application teams have their own runbook. This one is for the CCoE security
and platform side: handing the module to a team, and changing the baseline
once teams are running on it.

> File and variable names below are as the repository was built. Check them
> against `central-rules.tf` before executing anything — this document is the
> procedure, the repository is the truth.

---

## Part 1 · Who owns what

Stated once, because most confusion later traces back to here.

| | Owns | Does not own |
|---|---|---|
| **CCoE Security** | Rule content: central rules, rule set versions, Bot Manager version, the baseline version, exception policy | Azure Policy assignments, app team tfvars |
| **Platform team** | Azure Policy assignments and their scope, effect changes, exemptions, the management group | What the rules say |
| **Application team** | Their tfvars: their own rules in band 70–100, their exclusions, their gateway, their origin | Anything in bands 1–69 |

The boundary that matters: **an application team's tfvars cannot reach the
central rules.** They are in a CODEOWNERS-protected file, not a variable.
That is what makes "centrally managed" true rather than merely intended.

---

## Part 2 · Handing the module to an application team

### 2.1 The pack

Five artefacts. Send them together, in one message, with the covering note in
2.3 — not drip-fed as the team asks.

| | Artefact | What it is for | Status |
|---|---|---|---|
| 1 | **Module source and pinned version** | What they reference in their Terraform | See 2.2 — **you must pin a tag** |
| 2 | **App team runbook** (`WAF_App_Team_Runbook.docx`) | The full onboarding sequence, Step 0 to Step 10 | Have it |
| 3 | **Rule set migration runbook** | Only if they already have a WAF policy on any rule set | Have it |
| 4 | **Intake questionnaire** (`WAF_Onboarding_Intake.xlsx`) | Returns what you cannot read from their configuration | Have it |
| 5 | **A worked `workload.tfvars`** | Saves a round trip and sets the house style | **Does not exist yet — see 2.6** |

Three things stay internal and are **not** part of the pack: this runbook,
the Azure Policy definitions, and the design document. An application team
does not need them and sending them invites questions you do not want to
answer twice.

### 2.2 Pin a version. Do not let them track `main`.

The single most important line in the handover.

```hcl
module "waf_policy" {
  source = "git::https://<host>/<org>/AZ_WAF_design.git//infrastructure/modules/waf-policy-appgw?ref=v1.0.0"
  # ...
}
```

If a team references `main`, every central rule change you merge lands in
their next plan, unannounced, whenever that happens to be. You lose control
of rollout and they lose a predictable pipeline — and the "announce before
merging" step in 3.1 becomes meaningless, because the change already reached
them.

With a pinned tag, **you decide when each team moves**, and a central change
is a version bump you can schedule. Tag the repository before the first
handover.

### 2.3 The covering note

Paste-ready. Keeps the framing consistent across teams.

> Attached is everything you need to bring **<application>** onto the WAF
> baseline.
>
> **Start with the app team runbook.** Part 0 tells you which situation you
> are in and where to begin. If you already have a WAF policy on your
> gateway, read the rule set migration runbook as well — that is your path.
>
> **Please return the intake questionnaire**, plus a JSON export of your WAF
> policy and your Application Gateway. We read the technical detail from the
> export, so the questionnaire only asks what the configuration cannot tell
> us — mainly *why* each of your exclusions exists.
>
> **What the module does:** it creates a WAF policy carrying the central
> baseline. It does **not** create, modify or take ownership of your
> Application Gateway. Your gateway stays in your code; you add one property
> pointing at the policy the module produces.
>
> **Nothing blocks on day one.** The first change runs in Detection mode so
> we can see what would have been caught. Nothing is enforced until you and
> we agree it is safe, and rollback at any point is one line.
>
> The slowest item is usually a **named risk owner** — an individual, not a
> mailbox. Please start that now rather than when we reach it.

### 2.4 What the module does and does not do

Say this explicitly. Teams assume the worst unless told.

| Creates | Never touches |
|---|---|
| A WAF policy with the central rules | The Application Gateway |
| The pinned rule set version and Bot Manager | Listeners and backend pools |
| Their rules in band 70–100 | Certificates |
| Their exclusions, gated | The origin, and its access restrictions |

Attaching the policy is **their** change: one property, `firewall_policy_id`,
on a gateway they own.

### 2.5 Four things that will surface on their first plan

Warn them, or these read as the module being broken.

| What happens | Why | What they do |
|---|---|---|
| Custom rules outside priority **70–100** refused | Bands 1–69 are reserved for central rules | Renumber |
| Exclusions without owner, ticket, justification and expiry refused | The gate is the control | Raise the ticket, add the fields |
| An **`Allow`** action refused | A matching Allow terminates evaluation — every managed rule behind it is skipped | A negated **Block** if the need is "only these IPs may connect"; a scoped exclusion if one rule is firing |
| Every clean plan says **"2 to change"** | The two gate records stamp `plantimestamp()` | Nothing. It is the audit trail, not drift |

### 2.6 Known gaps in the pack

Fix these before the second team, if not the first.

| Gap | Impact | Effort |
|---|---|---|
| **No worked `workload.tfvars`** | Every team invents their own shape and you review five different styles | An hour |
| **No procedure for adding their own Block rule** | We tell teams to use a negated Block instead of an Allow, and never show them how. Your pilot team needs exactly this for `OnlyIPAllowed` | Half a day |
| **Contacts are placeholders** in app team runbook Part 6 | The first team with a problem finds "to be confirmed" | Ten minutes, needs a decision |
| **No repository tag** | Teams will pin to a commit hash or track `main` | Ten minutes |

### 2.7 What you need back before they start

- A **named risk owner** — an individual, not a mailbox
- JSON export of the WAF policy **and** the Application Gateway
- The completed intake questionnaire
- Which fields of the application carry personal data, for WAF log scrubbing
- Whether their gateway is in Terraform state, or was built another way

### 2.8 What you record

One row per onboarded application:

application · environment · gateway · risk owner · module version pinned ·
current mode · rule set version · date Detection started · date Prevention
started · open exceptions and their expiry dates

Without this you cannot answer "how far along are we", and you will be asked
that in every steering meeting from now on.

---

## Part 3 · Changing the baseline

Three procedures. All of them are a pull request against a
CODEOWNERS-protected file; none of them is a portal change.

> **The fact that governs all three: a central rule change reaches a workload
> on its next `terraform apply`, not immediately.** There is no push. A team
> that deploys monthly gets your change a month late. Plan around this, and
> see 3.4 for what to do when that is not acceptable.

---

### 3.1 Bumping the managed rule set version

**When:** Microsoft releases a new DRS version and you have decided to adopt
it, or the Terraform provider catches up on Front Door.

**Owner:** CCoE Security, with the platform team for the policy assignment.

**The order matters, and it is not the obvious one.**

**Step 1 — widen the Azure Policy assignment first.**
Ask the platform team to set `allowedRuleSetVersions` to **both** versions,
e.g. `["2.2","2.3"]`.

Do this *before* the code change. If you bump the code first, every newly
deployed workload reports non-compliant against a policy still demanding the
old version, and the dashboard fills with red that means nothing.

**Step 2 — announce it.**
The guardrail enforces the required version, so once the code moves, **every
workload below it fails its next plan**. That is the forcing function and it
is intended — but a team discovering it through a broken pipeline is a
different conversation from a team that was told.

Give a date. Name the workloads affected (`policy/resource-graph/waf-checks.kql`
query 6 lists rule set versions across the estate).

**Step 3 — change the code.**

```hcl
# central-rules.tf
required_appgw_ruleset = "2.3"        # was 2.2
required_afd_ruleset   = "2.1"        # unchanged unless the provider moved

# variables.tf
variable "appgw_ruleset_version" {
  default = "2.3"                      # was 2.2
  # the validation list also needs the new version adding
}
```

**Step 4 — bump `baseline_version`.**
Anything in `central-rules.tf` changing means the version moves. It is
stamped as a tag on every resource, and it is how you answer "who is still
running old central rules" with one query.

**Step 5 — update the tag policy's assignment.**
`waf-baseline-version-tag` checks the tag against an allowed list. Bumping
the version without updating that assignment means **every workload reports
non-compliant the next morning**. Widen it to both versions during the
rollout, exactly as in Step 1.

**Step 6 — test in sbx.**
`detection_ok_environments` permits Detection in sbx and dev. Prove the new
rule set there before the estate follows.

**Step 7 — narrow the policies again.**
Once the estate has moved, drop the old version from both assignments.
Leaving both accepted indefinitely means neither policy is enforcing
anything.

**Verify:** sbx is on the new version and passing; `waf-checks.kql` query 6
shows the estate converging; neither Azure Policy is reporting unexpected
non-compliance.
**Roll back:** revert the code change. Workloads that already applied stay on
the new version — you cannot un-apply them centrally, you would have to
ask teams to re-apply.
**Time:** an hour of work, weeks of rollout.

---

### 3.2 Adding or removing a central custom rule

**When:** a new mandatory protection, or an old rule that is no longer
earning its place.

**Owner:** CCoE Security.

**Where:** `central-rules.tf`, in the central rules locals. Not in
`variables.tf` — a rule an application team can reach is not a central rule.

**The bands:**

| Priority | Purpose |
|---|---|
| **1–9** | Emergency. Zero-day blocks. Evaluated before everything |
| **10–39** | Standing central rules |
| **40–69** | Rate limits |
| **70–100** | Application team's own. Not yours |

Priorities must be unique within a policy. Leave gaps — consecutive
numbering means the next insertion renumbers everything.

**To add:**

1. Write the rule in the correct band. Use `Block` or `Log`; never `Allow`
2. Set it to **`Log` first** if there is any doubt. A central rule that
   blocks legitimate traffic across every workload at once is the worst
   failure mode in this design
3. Bump `baseline_version`
4. Pull request. CODEOWNERS review is the control
5. Apply in sbx, watch the logs
6. Merge
7. It reaches each workload on their next apply

**To remove:**

Same path, with one extra thought: **what was that rule blocking?** Removing
it means that traffic now reaches applications. Check the logs for how often
it fired before deciding it is obsolete — a rule that never fires is a
candidate for removal; a rule that fires constantly is load-bearing.

**Verify:** the rule appears in `waf_central_rules_enforced` output; it
appears on the policy in sbx; the log shows it matching what you expected and
nothing else.
**Roll back:** revert the PR. Workloads pick it up on their next apply.
**Time:** an hour, plus a week of observation in sbx before merging.

---

### 3.3 Blocking an IP address

**When:** an address or range is attacking applications and you want it off
at the edge.

**Owner:** CCoE Security.

**Band 1–9**, so it evaluates before every other rule — including before an
application team's own allowlist. An emergency block beats a team's
`OnlyIPAllowed` rule, which is the behaviour you want.

**The rule:**

```hcl
{
  name     = "emergency-block-<reference>"
  priority = 5                                  # band 1-9
  action   = "Block"
  match_conditions = [{
    variable_name = "RemoteAddr"
    operator      = "IPMatch"
    match_values  = ["203.0.113.0/24", "198.51.100.7/32"]
  }]
}
```

**For a path rather than an address** — a zero-day on a known URI:

```hcl
{
  name     = "emergency-block-<cve>"
  priority = 3
  action   = "Block"
  match_conditions = [{
    variable_name = "RequestUri"
    operator      = "Contains"
    match_values  = ["/vulnerable/path"]
    transforms    = ["Lowercase"]
  }]
}
```

**Before you merge, check three things:**

- **Is the IP shared?** A NAT gateway or a corporate egress address may carry
  legitimate users as well as the attacker
- **Is it one of ours?** Partner integrations and monitoring come from fixed
  addresses too
- **Is the WAF the right layer?** For a non-HTTP attack, or an attack on a
  resource with no gateway in front, this rule does nothing. NSG or Azure
  Firewall is the control

**Add an expiry.** An emergency block with no review date becomes permanent
and nobody remembers why. Record the date and the reason in the comment, and
schedule the review.

**Verify:** the rule appears on the policy; a request from a test address in
the range returns 403; legitimate traffic is unaffected.
**Roll back:** revert the PR.
**Time:** 30 minutes to write and review. **Hours to days to reach every
workload** — see 3.4.

---

### 3.4 When "next apply" is not fast enough

The honest limitation in this design: a central rule reaches a workload when
that workload next applies. For a zero-day, that is too slow.

Three options, worst to best:

**Option A — ask teams to run their pipeline.** Slow, needs everyone awake,
but changes nothing structurally. Fine for a Tuesday, useless at 3am.

**Option B — the CCoE applies on their behalf.** Needs the right permissions
in their subscription and their pipeline not to conflict. Agree this in
advance or it will not be available when you need it.

**Option C — break glass: edit the WAF policy directly in Azure.**

Immediate, and it creates drift. Do it only for an active incident, and:

1. Record what you changed and where, at the time, not afterwards
2. Expect `waf-baseline-version-tag` and the drift queries to flag it —
   **that is correct**, do not suppress it
3. **Reconcile within 48 hours**: the same change goes into
   `central-rules.tf` through the normal path, and the manual edit is removed
4. Until reconciled, the next `terraform apply` on that workload reverts your
   emergency change

Point 4 is the one that catches people. A manual edit is not durable — the
pipeline will undo it, possibly at a bad moment.

**Decide which of these you are using before you need it**, and write the
answer here. An untested emergency procedure is not a procedure.

---

## Part 4 · Verification after any central change

Four checks, in order. Two minutes.

1. **sbx first.** Nothing merges that has not applied cleanly in sbx
2. **The output.** `waf_central_rules_enforced` lists what the module
   believes is enforced
3. **The live policy.** Portal → the WAF policy → JSON View. The rule is
   present, at the priority you intended
4. **The logs.** It matches what you expected, and nothing else. A rule that
   fires on everything is worse than no rule

For an estate-wide view, `policy/resource-graph/waf-checks.kql` — query 1 for
baseline version drift, query 6 for mode and rule set version.

---

## Not yet written

This covers the handover and the three change procedures. Still to do, in
rough order of how soon you will want them:

- **Exceptions**: when the gate refuses one, when one expires and blocks a
  team's deploy, how approval works outside the pipeline
- **Drift**: reading the compliance view, what each Resource Graph check
  means, and what to do when someone has edited a policy in the portal
- **Azure Policy operations**: requesting an effect change, granting an
  exemption, and the conditions for moving Audit to Deny
- **Incidents**: a team reports the WAF has blocked them; emergency rollback
- **Ownership and handover**: who holds this when you are not here
