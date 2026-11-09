# Moving an existing WAF policy onto the baseline

For application teams whose gateway already has a WAF policy, on any rule set.

The baseline is **DRS 2.2** on Application Gateway, **DRS 2.1** on Front Door
(a provider limit, not a choice), and **Bot Manager 1.1** on both. Default
Rule Set 2.2 runs at **Paranoia Level 1**, and that is the accepted position —
you do not need to enable PL2 rules.

Nothing in this runbook blocks a single request until Step 11. Everything
before it is additive, reversible, or in Detection mode.

---

## Part 0 · Which starting point are you?

Find your rule set: portal → your WAF policy → **Managed rules**, or in the
JSON view at `properties.managedRules.managedRuleSets[]`.

| What you have | What the move means | Go to |
|---|---|---|
| **OWASP CRS 3.0, 3.1 or 3.2** | Rule set **type** change, not a version bump. Rule group names change and some rules no longer exist | Step 1 |
| **DRS 2.0 or 2.1** | Version change within the same type. Group names are stable; some rules still differ | Step 1 |
| **DRS 1.x, or CRS 2.2.9** | Older than the documented upgrade path. May need two hops | **Talk to us first** |
| **No managed rule set at all** | Only custom rules are running. The simplest case — nothing to migrate | Step 5 |
| **A legacy WAF *configuration*, not a policy** | Settings stored inline on the gateway. Different job, do it first | Runbook Part 3.8 |
| **Front Door, any version** | Same sequence, target 2.1, different field names | Variant A |

Microsoft documents the upgrade to DRS 2.2 from CRS 3.0, CRS 3.1, CRS 3.2 and
DRS 2.1. If you are on something older than that, say so at Step 1 rather
than finding out mid-change.

> **Three things that do not change, whatever rule set you are on.** Your
> custom rules, your policy settings (mode, body size limits, file upload
> limits) and global exclusions are unaffected by a rule set change. Only
> managed-rule customisations — disabled rules, rule overrides and
> rule-scoped exclusions — are at risk.

---

## Step 1 · Export, and keep the export

This is your rollback artefact and the input to every step below. Do not
start without it.

Portal → your WAF policy → **Overview** → **JSON View** (top right) → copy
all. Save it as `waf-policy-before-<date>.json`, somewhere you will still be
able to find in three months.

Do the same for the Application Gateway itself.

**Verify:** you can open the file and see `managedRules`, `customRules` and
`policySettings`.
**Roll back:** nothing has changed.
**Time:** 10 minutes.

---

## Step 2 · Inventory what you have customised

Three lists. Read them out of the export rather than from memory.

| List | Where in the JSON | What to record |
|---|---|---|
| **Custom rules** | `properties.customRules[]` | Name, priority, action, what it matches |
| **Disabled rules and overrides** | `properties.managedRules.managedRuleSets[].ruleGroupOverrides[]` | Rule group name, rule ID, state, action |
| **Exclusions** | `properties.managedRules.exclusions[]` | Match variable, selector, and the rule groups each is scoped to |

For every exclusion and every disabled rule, you also need something that is
**not** in the JSON:

- What broke that caused it?
- Which application feature does it protect?
- When was it added, and by whom?
- Is there a ticket or approval reference?
- **Is it still needed?**

An exclusion nobody can explain is a candidate for removal rather than
migration. "Unknown" is a fair answer and tells us something useful.

**Verify:** three written lists, and a why against each entry on two of them.
**Roll back:** nothing has changed.
**Time:** an hour, more if you have to go asking.

---

## Step 3 · Check each customisation survives the move

This is the step that prevents a failed change window.

**Every rule you have customised must still exist in the target rule set.**
An override naming a rule that the new rule set does not contain makes the
whole policy update **fail**, with:

```
The override Rule '<id>' is unknown for RuleGroup '<group>'
```

**And if you are coming from CRS, the rule group names change.** Examples:

| CRS group name | DRS group name |
|---|---|
| `REQUEST-941-APPLICATION-ATTACK-XSS` | `XSS` |
| `REQUEST-942-APPLICATION-ATTACK-SQLI` | `SQLI` |
| `Known-CVEs` | `MS-ThreatIntel-CVEs` |

Those are examples, not the full mapping. Send us your list from Step 2 and
we will map it with you — this is not a thing to do alone at 2am.

Coming from DRS 2.0 or 2.1, group names are stable, but individual rules can
still have been removed. The check is the same.

**Verify:** every rule ID in your overrides list is confirmed present in the
target, with its correct group name.
**Roll back:** nothing has changed.
**Time:** 1–2 hours.

---

## Step 4 · Decide what to keep

Each item from Step 2 gets one of three outcomes.

| | Outcome | What it means |
|---|---|---|
| **Keep** | Still needed | It is re-raised as a proper exception: scoped to a rule group, with a justification, a named risk owner, a ticket reference and an expiry date |
| **Drop** | Obsolete, or nobody can say what it is for | It does not come across |
| **Re-decide** | The need is real but the fix was blunt | We find a narrower one together |

**Your custom rules move into priority band 70–100.** Bands 1–69 are
reserved for central rules. If a rule of yours currently sits at priority 5
it needs renumbering, and the pipeline will refuse it until it does.

> **On allowlisting partner IP addresses.** An `Allow` action is refused in
> the application band, because a matching Allow **stops all further
> evaluation** — every managed rule behind it is skipped and that traffic
> reaches your application uninspected. Microsoft's own wording: *"Allow –
> Authorizes the transaction, skipping all other rules."*
>
> If what you need is *only these IP addresses may reach the application*,
> the correct rule is a **Block with negation** — block everything that is
> **not** in your list. Same access control, and permitted traffic is still
> fully inspected. That is supported and encouraged.

**Verify:** every item from Step 2 has a decision written against it.
**Roll back:** nothing has changed.
**Time:** a session with us.

---

## Step 5 · Build the new policy, attached to nothing

The module creates a new WAF policy resource carrying the baseline, in
**Detection**, associated with no gateway.

Nothing in the request path changes. Your existing policy is still attached
and still doing its job.

**Verify:** the new policy exists; your gateway still points at the old one.
**Roll back:** delete the new policy. Nothing depended on it.
**Time:** one pipeline run.

---

## Step 6 · Capture your "before"

**Do not skip this, and do not do it later — later is not available.**

Only one WAF policy can be attached to a gateway at a time. The moment you
attach the new policy, the old one is detached and **stops producing logs
entirely**. If you have not captured its behaviour first, you have nothing to
compare against.

Collect **at least a week** of logs from the existing policy while it is
still attached. A week that includes your batch runs, your month-end, or
whatever your unusual traffic is.

```kusto
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where TimeGenerated > ago(7d)
| summarize count() by ruleId_s, action_s, requestUri_s
| order by count_ desc
```

**Verify:** you have a week of data and can describe what normally fires.
**Roll back:** nothing has changed.
**Time:** a week of waiting, ten minutes of work.

---

## Step 7 · Switch to the new policy, in Detection, with no exclusions

One line: the gateway's `firewall_policy_id` points at the new policy.

**Carry none of your exclusions across yet.** This is deliberate. Detection
blocks nothing, so there is no risk — and running clean shows you what the
new rule set actually fires on. Port your old exclusions in first and you
have hidden the very thing you are trying to measure, and you will carry
obsolete exclusions forever.

> **Never do this part in the portal.** Upgrading a rule set through the
> portal **resets** managed-rule customisations. The pipeline preserves them.
> If someone offers to "just change it quickly in the portal", the answer is
> no.

**Verify:** the gateway shows the new policy attached, mode Detection, and
your probe appears in the log.
**Roll back:** point `firewall_policy_id` back at the old policy. One line,
minutes. **The old policy still exists — do not delete it.**
**Time:** a change window, though nothing should be visible to users.

---

## Step 8 · Compare the two weeks

Run another week and compare against Step 6.

You are looking for three things:

- **What the new rule set catches that the old one did not.** Some will be
  genuine, some will be false positives
- **Anything that used to be excluded and is now firing.** Expected — you
  deliberately did not carry the exclusions over
- **Anything firing in volume on a single field.** That is usually one
  application behaviour, and usually one exclusion fixes it

Newly introduced rules may be in **Log** mode by design, so you can see their
effect before they can block. Note which they are.

**Verify:** you can explain every rule that fires more than a handful of
times.
**Roll back:** as Step 7.
**Time:** a week, and a couple of hours reading.

---

## Step 9 · Tune

Each genuine false positive becomes a scoped exclusion — one field, one rule
group, with a justification, a named risk owner, a ticket reference and an
expiry date.

Not a copy of the old exclusion. A fresh decision, based on what you just
observed.

The pipeline refuses an exclusion that is unscoped, undated, unowned or
unexplained. That is the control working, not the tooling being awkward.

**Verify:** the rule stops appearing for that field, and still appears for
others.
**Roll back:** remove the exclusion block.
**Time:** two or three sessions over a fortnight.

---

## Step 10 · Bot Manager, separately

Only when the rule set has settled. One variable at a time — if you move the
rule set and Bot Manager together and something breaks, you will not know
which did it.

Expect new detections and some new false positives. Treat them exactly as
Step 9.

**Time:** a few days of observation.

---

## Step 11 · Switch to Prevention

Only when Step 8's log is quiet and Step 9 is finished. This is the first
moment anything is blocked.

**Before:** agree what "it went wrong" looks like, and who is contactable.
**Verify:** a known-bad request returns 403; your application still works.
**Roll back:** mode back to Detection. One variable.
**Time:** a change window, and people watching.

---

## Step 12 · Retire the old policy

Not on the same day. Leave it for a **fortnight** after Prevention — it is
your fast way back and it costs nothing to keep.

Then delete it, and keep the Step 1 export.

---

## Variant A · Front Door

Same sequence, four differences:

- **The target is DRS 2.1**, not 2.2. The Terraform provider does not reach
  2.2 on Front Door yet. This is tracked and will change
- **Premium is required.** Front Door Standard supports custom rules only —
  managed rule sets are not available, so the baseline cannot be attached at
  all. The upgrade is in place, takes minutes and causes no downtime, but it
  is **one way**
- **After a Standard → Premium upgrade, check the managed rules are actually
  on.** The upgrade copies your policies but does not enable managed rules.
  You can end up with a Premium profile, a WAF policy attached, and nothing
  being inspected
- **Field names differ.** `policySettings.enabledState` rather than `state`,
  and custom rules nest under `customRules.rules[]`. Only matters if you are
  reading the JSON yourself

---

## Variant B · Your gateway is shared with other applications

Say so at Step 1. This changes the design, not just your plan.

A gateway-level policy applies to every listener that has no policy of its
own, so an exclusion raised for your application would weaken protection for
everyone behind that gateway. Per-listener policies solve that, but each one
then carries the full baseline independently, because **scopes do not
combine** — a listener's policy *replaces* the gateway's rather than adding
to it.

If you are on a shared gateway you are a design conversation, not a standard
migration.

---

## What we need from you, and when

| When | What |
|---|---|
| Before Step 1 | A named risk owner — an individual, not a mailbox |
| Step 1 | The JSON export of the policy and the gateway |
| Step 2 | Your three lists, and the *why* behind each exclusion |
| Step 3 | Your override list, for mapping |
| Step 6 | Confirmation you have a week of baseline logs |
| Step 7 | A change window |
| Step 9 | Which fields of your application carry personal data, so WAF log scrubbing can be configured |
| Step 11 | A change window, and agreement on what "it went wrong" looks like |
| Any time | Anything awkward: partner allowlists, client certificates, fixed source IPs, non-standard ports, shared gateways |

---

## The short version

1. Export what you have. Keep it.
2. List your customisations, and why each exists.
3. Check each one survives the move.
4. Decide keep, drop or re-decide.
5. Build the new policy, attached to nothing.
6. **Capture a week of logs before switching** — it is not available afterwards.
7. Switch, in Detection, with no exclusions.
8. Compare.
9. Tune.
10. Bot Manager.
11. Prevention.
12. Retire the old policy a fortnight later.

Rollback at any point between 7 and 12: point `firewall_policy_id` back. One
line, minutes.
