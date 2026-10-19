# Centrally managed WAF with a validated exception flow

Demo runbook —  Wednesday.

---

## The thing being demonstrated

Not "we put a WAF in front of an app". The operating model:

**Security owns the rules. Application teams own their own band, and their
exceptions are validated by the pipeline before anyone reviews them.**

Three claims, each shown rather than asserted:

1. An application team **cannot** change, reorder or remove a central rule.
2. An application team **can** add its own rules, within a band, without
   waiting for security.
3. An exception to the WAF is **scoped, justified, owned and temporary** — and
   the pipeline, not a reviewer, enforces all four.

---

## A constraint to state out loud, early

An Azure WAF policy cannot be shared across subscriptions or regions. An
Application Gateway policy must live in the same subscription *and* region as
its gateway.

So there is no single policy covering the estate, and nobody should promise
one. What is central is the **definition** — one file, rendered into every
policy the platform creates.

> Central definitions, federated enforcement.

Say this before the demo rather than after a question, because it is the first
thing an architect in the room will test you on.

---

## Part 1 — the pull request that gets refused (5 minutes)

No Azure resources. Nothing to pay for. Runs in about fifteen seconds.

Open `infrastructure/environments/sbx/workload.tfvars`. This is the file an
application team owns. Point out what is **not** in it: there is no
`appgw_central_rules`. The central rules live in
`infrastructure/workload/central-rules.tf`, which `CODEOWNERS` assigns to
security. A pull request touching it cannot merge without their approval.

Then make four edits, one at a time, push, and show the check go red.

| Edit | What the pipeline says |
|---|---|
| `priority = 70` → `20` | *Application rules must use priority 70-100. Bands 1-69 belong to security (1-9 emergency, 10-39 central, 40-69 rate limits) and are defined in central-rules.tf.* |
| `rule_group_name = ""` | *NO BLANKET EXCLUSIONS. Every exclusion must name the rule group it applies to...* |
| `justification = "false positive"` | *Every exclusion needs a justification of at least 30 characters... 'false positive' is not a justification.* |
| `expires = "2026-01-01"` | *EXPIRED WAF EXCLUSION — this plan is blocked.* |

All four are in the comment block at the bottom of the tfvars, so you can read
them off the screen rather than remembering them.

**The one to dwell on is the last.** Nobody has to remember to review that
exclusion. The next time anyone plans this workload after the expiry date, the
pipeline raises it. The default outcome of forgetting about an exception is
that it is removed, not that it quietly becomes permanent.

If there is time, show two more:

- `owner = "cloud-team"` → *owner must be a named person's email address, not
  a team alias. Teams do not answer questions in six months.*
- `expires = "2027-12-31"` → *WAF EXCLUSION GRANTED FOR TOO LONG... A year is
  not an exception, it is a decision nobody made.*

---

## Part 2 — what it looks like when it passes (2 minutes)

Revert to the good file and show the plan output:

```
waf_central_rules_enforced = {
  appgw = [
    { name = "blockSensitivePaths",       priority = 10, action = "Block" },
    { name = "blockDangerousHttpMethods", priority = 11, action = "Block" },
    { name = "rateLimitPerClientAddr",    priority = 40, action = "Block" },
  ]
}

waf_application_rules = {
  appgw = [ { name = "logLegacyApiVersion", priority = 70, action = "Log" } ]
}

waf_exception_register = [
  {
    platform      = "Application Gateway"
    scope         = "REQUEST-942-APPLICATION-ATTACK-SQLI"
    field         = "RequestArgNames:filter"
    narrowed_to   = "942430"
    justification = "Catalogue search sends boolean filter expressions..."
    owner         = "..."
    ticket        = "SEC-1001"
    expires       = "2026-12-15"
  },
]
```

Three outputs, three audiences:

- **`waf_central_rules_enforced`** — what the platform guarantees, whatever the
  application team asked for.
- **`waf_application_rules`** — what the team added for itself.
- **`waf_exception_register`** — every exception in force, with an owner and an
  expiry date. This is the answer to *"how do we evidence this at audit"*:
  `terraform output waf_exception_register`, no portal, no spreadsheet, no
  asking around.

---

## Part 3 — live enforcement (optional, needs phase 2)

Only if `enable_appgw = true` has been applied. If it has not, say so and show
Part 1 and 2 only — a demo that admits its boundary is more convincing than one
that blurs it.

With the gateway up:

1. Send a request to a sensitive path — `/.env` — and show it blocked by
   central rule priority 10, which the application team never asked for and
   cannot remove.
2. Send the catalogue-search request that trips rule 942430 and show it allowed
   because of the exclusion.
3. Show in Log Analytics that **the rest of** REQUEST-942 still fired on other
   requests — the exclusion narrowed one field on one rule, not the group.

Point 3 is the one that matters. It is the difference between an exception and
an off switch, and it is the thing a blanket exclusion would have destroyed.

---

## Questions to expect, and honest answers

**"Can we have one WAF policy for everything?"**
No. The policy must be in the same subscription and region as the gateway.
What is central is the rule definition file, not the policy object.

**"What stops a team editing central-rules.tf anyway?"**
CODEOWNERS plus branch protection. **Check this before the demo** — CODEOWNERS
does nothing unless *Require review from Code Owners* is enabled on `main`, and
the team slug in the file has to be a real GitHub team. Placeholder is
`@<org>/cloud-security`. Without both, the file is documentation, not a
control, and it would be worse than useless to claim otherwise in the room.

**"What happens when the rule set is upgraded?"**
A managed rule set version change resets exclusions to the new set's defaults.
They are held in code precisely so they can be re-applied and reconciled. This
is not yet automated — it is an open item, not a solved one.

**"Does this work for AWS?"**
The pattern transfers, the implementation does not. Not demoed, not claimed.

**"Why is Front Door different from Application Gateway?"**
Because the platforms are. Three documented asymmetries, all found in the
provider docs rather than in production:
- App Gateway supports DRS 2.2, Front Door only up to 2.1.
- Front Door supports `RequestBodyJsonArgNames` exclusions, App Gateway does
  not — so a JSON-body false positive may be untunable on Pattern B.
- App Gateway scopes an exclusion with a field. Front Door scopes it by
  nesting, and an override block with no rules **disables the whole rule
  group**. The code attaches Front Door exclusions to named rule IDs to avoid
  that trap entirely.

That third one is worth volunteering. It is the kind of thing that bites in
production and it was caught by reading the provider documentation.

---

## Before you walk in

- [ ] Branch protection on `main` has *Require review from Code Owners* on
- [ ] `@<org>/cloud-security` in `.github/CODEOWNERS` replaced with the real team slug
- [ ] One rehearsal of the four failing edits, so the timing is known
- [ ] Decide whether Part 3 is in or out, and say which at the start

---

## What this is not

Stated plainly so nobody leaves with a wrong impression.

- Not deployed beyond the sandbox.
- Not tested at scale — one workload, one subscription.
- Prevention mode not yet exercised; the policy has run in Detection throughout.
- The rule-set-upgrade reconciliation is designed, not built.
- AWS is untouched.
