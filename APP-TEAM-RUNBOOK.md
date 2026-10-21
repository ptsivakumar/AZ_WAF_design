# Bringing an internet-facing application under the WAF baseline

**Step-by-step runbook for application teams**
Cloud Centre of Excellence · Version 1.0 · 21 October 2026

This is the detailed companion to the onboarding guide. The guide explains
*what happens and why*; this document is what you actually do, in order, with
the verification and the way back at every step.

---

## Part 0 · Which situation are you in

Find your application below. The worked example in Part 1 is **A3**, because it
is the most common and the most awkward.

| | Situation | Where to start |
|---|---|---|
| **A1** | Public App Service / Function, no gateway at all | Part 2 — you need a gateway first |
| **A2** | Application Gateway on `Standard_v2` — cannot run WAF rules | Part 1, from Step 2 |
| **A3** | Application Gateway on `WAF_v2`, serving internet traffic, no baseline policy | **Part 1, from Step 0** |
| **A4** | Application Gateway with its own WAF policy already | Part 1, plus Part 3.1 |
| **A5** | Front Door in front, no WAF policy | Part 3.4 |
| **A6** | Already behind the baseline, blocking, origin closed | Nothing to do — tell us so we can record it |
| **A7** | No public HTTP endpoint | Out of scope — tell us, so it leaves the backlog |

> **Before you start anything**, you need a **named risk owner** for the
> application — an individual who can accept residual risk, not a team mailbox.
> This reliably takes longer to arrange than any technical step here. Start it
> on day one.

---

## Part 1 · Worked example — an Application Gateway already serving the internet

### The starting state

Throughout this example:

| | |
|---|---|
| Gateway | `appgw-claims-prd`, SKU `WAF_v2`, public IP `20.50.x.x` |
| Listener | `claims.example.com` on port 443 |
| Backend | App Service `claims-prd` |
| Problem 1 | No WAF policy attached — the gateway is a load balancer with TLS |
| Problem 2 | `claims-prd.azurewebsites.net` answers directly from the internet |

Problem 2 is the one that matters. Fixing problem 1 alone gives you a firewall
with a door next to it.

---

### Step 0 · Inventory your own gateway

**Do this.** Collect the following and send it to the CCoE with your intake
form. Everything is readable with Reader on your own subscription.

```bash
RG=rg-claims-prd
GW=appgw-claims-prd

# SKU — must be WAF_v2 to run WAF rules at all
az network application-gateway show -g $RG -n $GW --query "sku"

# is any WAF policy attached, globally or per listener?
az network application-gateway show -g $RG -n $GW \
  --query "{global:firewallPolicy.id, listeners:httpListeners[].{name:name, policy:firewallPolicy.id}}"

# what the gateway talks to
az network application-gateway show -g $RG -n $GW \
  --query "backendAddressPools[].backendAddresses"

# the public IP the gateway reaches your origin from
az network public-ip show -g $RG -n <gateway-public-ip-name> --query ipAddress -o tsv
```

**Why the listener query matters.** A WAF policy attached to a listener
**replaces** the gateway's policy for that listener's traffic — it does not add
to it. If any listener already has its own policy, say so now; it changes the
plan.

**Verify:** you can answer all four questions above.
**Roll back:** nothing has changed.
**Time:** 15 minutes.

---

### Step 1 · Decide where your gateway is defined

This decides the next three steps, so answer it honestly.

| Your answer | What happens |
|---|---|
| **It's in our Terraform / Bicep** | Best case. We publish the policy, you add one line. Step 3 onward |
| **It was built in the portal** | You either bring it under code first (recommended), or we attach the policy by hand once and adopt it afterwards |
| **I don't know** | Check for a state file or a pipeline that deploys it. If nobody can find one, treat it as portal-built |

If it was portal-built, importing it into Terraform is a one-off job we will do
*with* you. An Application Gateway is a large resource and an import that goes
wrong in production is unpleasant, so we do it in a non-production copy first.

**Verify:** you know which of the three applies.
**Time:** 30 minutes, or a day if you have to go looking.

---

### Step 2 · Only if your gateway is `Standard_v2`

A `Standard_v2` gateway cannot have a WAF policy at all. It has to move to
`WAF_v2` first.

Standard_v2 and WAF_v2 are the same generation, and Microsoft supports moving
between them — but treat it as a change with a reconfiguration window, and
**confirm the current procedure with the platform team before you schedule it.**
Do not discover the answer during the change.

**Verify:** `az network application-gateway show --query "sku"` returns
`WAF_v2`, and the application still serves traffic.
**Roll back:** the SKU can be moved back.
**Time:** a change window. Plan for an hour even if it takes ten minutes.

---

### Step 3 · Create the baseline policy

You do not write this. The pipeline creates a WAF policy in **your**
subscription and **your** region — it has to be both, because Azure requires it.

Your pull request adds a module block:

```hcl
module "waf_policy" {
  source = "git::<platform-repo>//modules/waf-policy-appgw?ref=<version>"

  name                = "waf-claims-prd"
  resource_group_name = azurerm_resource_group.claims.name
  location            = azurerm_resource_group.claims.location

  environment = "prd"
  mode        = "Detection"      # Detection first. Always.
}
```

> Module source and version pin are illustrative — a published, versioned
> module is still outstanding work. Until it exists, we give you the exact block
> to paste.

**What arrives with it, that you did not ask for and cannot remove:** the
managed rule set at the baseline version, Bot Manager, the mandatory central
rules, and the rate limits. They come from a file in the platform repository
that your configuration has no syntax to reach.

**What the plan should say:** one WAF policy to add. Nothing else. If the plan
proposes changing or replacing your gateway at this step, **stop and tell us** —
that is not supposed to happen yet.

**Verify:** the policy exists in the portal, mode Detection, and is attached to
nothing.
**Roll back:** destroy the policy. Nothing is using it.
**Time:** one pipeline run.

---

### Step 4 · Attach it, in Detection mode

One line on your gateway resource:

```hcl
resource "azurerm_application_gateway" "claims" {
  # everything else unchanged — listeners, certificates, routing, backends

  firewall_policy_id = module.waf_policy.id        # the only line you add
}
```

**Read the plan carefully before approving.** You are looking for an in-place
update that sets `firewall_policy_id` and changes nothing else. A plan that
wants to destroy and recreate the gateway is a red flag — stop.

**What changes for your users:** nothing. Detection mode inspects and logs. It
blocks nothing at all.

**Verify:**
- Portal → your gateway → *Web application firewall* shows the policy attached
- Your application still serves traffic normally
- Firewall logs are arriving (Step 5)

**Roll back:** remove the line, re-apply. Minutes.
**Time:** one pipeline run plus a few minutes of gateway reconfiguration.

---

### Step 5 · Prove that inspection is actually happening

Do not skip this. An attached policy that is logging nothing looks identical to
one that is working.

**Send a probe.** From a browser, against your own hostname:

```
https://claims.example.com/.git/config
```

That path is in the mandatory central rules. In Detection mode you will get
your application's normal 404 — the WAF logs it and allows it through. That is
correct behaviour at this stage.

**Then look for it.** In Log Analytics:

```kusto
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where TimeGenerated > ago(15m)
| project TimeGenerated, action_s, ruleId_s, Message, requestUri_s, clientIp_s
| order by TimeGenerated desc
```

> Field names differ depending on whether your diagnostic settings use the
> **AzureDiagnostics** table or the resource-specific **AGWFirewallLogs** table.
> If the query above returns nothing, check which mode you are in before
> concluding the WAF is not working.

**Verify:** you can see your own probe in the log, with a rule ID against it.
**If you see nothing:** diagnostic settings are not sending firewall logs to the
workspace. Fix that before going any further — everything after this step
depends on being able to read these logs.
**Time:** 20 minutes.

---

### Step 6 · Find out who calls your origin directly

**This is the step that takes real time, and the one that cannot be skipped.**

Right now your App Service answers the internet directly. In Step 7 you close
that. Anything we have not found by then stops working, and the failure
typically shows up days later at 02:00, not while you are watching.

#### What we query

Two weeks of origin access logs, looking for requests that did not come through
the gateway:

```kusto
AppServiceHTTPLogs
| where TimeGenerated > ago(14d)
| extend viaGateway = (CIp == "20.50.x.x")          // your gateway's public IP
| where not(viaGateway)
| summarize requests = count(),
            firstSeen = min(TimeGenerated),
            lastSeen  = max(TimeGenerated),
            paths     = make_set(CsUriStem, 20)
        by CIp, UserAgent
| order by requests desc
```

> Verify the column names against your own workspace before trusting the
> result. If your origin is not App Service, the table differs — ask us.

#### What you do

The log tells us what called you **during those two weeks**. It cannot tell us
about anything that runs less often than that. Go and ask:

- [ ] Partner integrations — anyone with your origin hostname in an allowlist
- [ ] Other internal applications, especially any that hardcoded the origin name
- [ ] Batch jobs, including on-premises ones, and quarterly or month-end jobs
- [ ] Monitoring, synthetic probes and uptime checks
- [ ] CI/CD smoke tests that hit the origin hostname directly
- [ ] Reporting or BI tools pulling data
- [ ] Disaster-recovery procedures that bypass normal ingress

For each caller found, record: who owns it, what it needs, and whether it can
move to the public hostname instead of the origin.

**Verify:** you have a written list, and someone has said out loud "that is
everything I know of".
**Roll back:** n/a — nothing has changed.
**Time:** two weeks elapsed. A few hours of your effort, spread.

---

### Step 7 · Close the route around the gateway

This is the highest-risk step, and the one that makes everything before it
worth doing.

#### What gets configured

```hcl
site_config {
  # deny by default on the main site
  ip_restriction_default_action = "Deny"

  # allow only this gateway's public IP
  ip_restriction {
    name       = "allow-our-appgw"
    action     = "Allow"
    priority   = 110
    ip_address = "20.50.x.x/32"
  }

  # THE SECOND DOOR — deny by default here too
  scm_ip_restriction_default_action = "Deny"
}
```

> ### App Service has two front doors
>
> `claims-prd.azurewebsites.net` is the main site.
> `claims-prd.scm.azurewebsites.net` is the Advanced Tools / SCM site — the
> **same application**, reached a different way, with its **own separate
> access restrictions**.
>
> We found this by locking the main site in our sandbox and still getting
> through. A lockdown that names only the main site is not a lockdown.
>
> Deployment through the Azure control plane is unaffected. Anything that
> reaches the SCM hostname directly is not — if you have tooling that does,
> raise it now.

#### Before you apply

- Schedule it in your change window, with the people who own the callers from
  Step 6 contactable.
- Have the rollback ready to paste, not ready to write.

#### Verify — all four

1. `https://claims.example.com/` still works (through the gateway)
2. `https://claims-prd.azurewebsites.net/` now fails
3. `https://claims-prd.scm.azurewebsites.net/` now fails
4. Your deployment pipeline still deploys

#### Watch for 72 hours

Set a reminder. The callers you missed surface late, not immediately. Check
origin logs for refused requests:

```kusto
AppServiceHTTPLogs
| where TimeGenerated > ago(24h) and ScStatus == 403
| summarize count() by CIp, UserAgent, CsUriStem
| order by count_ desc
```

**Roll back:** set `ip_restriction_default_action = "Allow"` and re-apply.
Minutes. Do this first and investigate afterwards — do not debug with a partner
integration down.
**Time:** a change window, plus 72 hours of attention.

---

### Step 8 · Tune

The WAF has been logging since Step 4. Now read it.

#### What fired, and how often

```kusto
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where TimeGenerated > ago(14d)
| summarize hits = count() by ruleId_s, Message, requestUri_s
| order by hits desc
| take 50
```

#### Deciding what each one is

For every rule that fires more than a handful of times, decide:

| It is | Do |
|---|---|
| A real attack | Nothing. The WAF will block it in Step 9. Good |
| A false positive on one field | Raise a scoped exclusion — below |
| A false positive everywhere | Talk to us. That is usually a sign the rule set version or the profile is wrong for your traffic |

> **"Matched" is not "would have been blocked".** Rules carry an anomaly score —
> Critical 5, Error 4, Warning 3, Notice 2 — and a request is blocked at a total
> of 5 or more. A single Warning-level match logs and passes. Always check
> whether the request would actually have been refused before you write an
> exclusion for it.

#### Writing the exclusion

Narrowest thing that fixes it. Real example:

```hcl
appgw_exclusions = [
  {
    match_variable  = "RequestArgNames"
    selector        = "filter"
    operator        = "Equals"
    rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
    excluded_rules  = ["942430"]

    justification = "Catalogue search sends boolean filter expressions such as 'type eq book or type eq journal'. Rule 942430 counts the special characters as SQL. Confirmed in Detection over 3 days, no true positives on this field."

    requested_by = "you@example.com"
    risk_owner   = "named.person@example.com"

    ticket  = "SEC-1001"
    expires = "2026-12-15"
  },
]
```

This excludes **one rule** from **one field**. Every other rule in the SQLI
group, and every other managed rule, still inspects that request.

#### What the pipeline refuses, and why

| Refused | Reason |
|---|---|
| No `rule_group_name` | An unscoped exclusion stops that field being inspected by *every* managed rule |
| Justification under 30 characters | Somebody has to understand this decision in six months |
| `risk_owner` is not an email address | A bare team name is refused |
| Expiry missing, past, or beyond the environment ceiling | 90 days sandbox and dev, 60 staging, 30 production |
| No ticket reference | It is the link to the organisation's exception record |
| Your own rule outside priority 70–100 | Bands below 70 belong to security |

**You merge this yourself.** There is no security approval queue.

**Verify:** the rule stops appearing in the log for that field, and still
appears for others.
**Roll back:** remove the exclusion block.
**Time:** 2–3 sessions over two weeks.

---

### Step 9 · Switch to blocking

Only when Step 8 is quiet.

```hcl
mode = "Prevention"
```

#### Before

- Change window, during business hours, with people watching
- Agree what "it went wrong" looks like — error rate, specific journeys
- Tell your support desk it is happening

#### Verify

1. Your main user journeys still work. Test them, do not assume
2. The probe from Step 5 now returns **403** instead of 404
3. Error rates and latency are normal

```kusto
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where TimeGenerated > ago(1h) and action_s == "Blocked"
| summarize count() by ruleId_s, requestUri_s, clientIp_s
| order by count_ desc
```

Anything in that list that is a real user is a false positive you missed. Add
the exclusion, or go back to Detection while you work it out.

**Roll back:** `mode = "Detection"`. Inspection continues, blocking stops.
Minutes.
**Time:** a change window plus a day of attention.

---

### Step 10 · Steady state

**Your exclusions expire.** On the expiry date nothing happens to your running
application. The **next deployment** of your workload is refused until someone
renews with a fresh ticket and date, or deletes the exclusion because the
application was fixed.

Nobody has to remember to review them.

**What you now own:** your own rules in band 70–100, your exclusions, and
telling us when the application changes shape — a new hostname, a new
integration, a new upload path.

**What changes under you, without you doing anything:** the mandatory central
rules and the rule-set version, when security updates them. You will see them
in your plan output.

---

## Part 2 · If you have no gateway at all

Situation **A1** — a public App Service or Function with nothing in front.

The sequence is the same from Step 3 onward, with two differences at the start.

**You need a gateway built.** We build it with you, in your subscription and
region. It needs a dedicated subnet — Application Gateway cannot share one.

**There is a DNS cutover.** Your hostname has to point at the gateway instead of
the origin. That is the one step this path has and Part 1 does not:

- Build the gateway with your certificate and listener, backend pointing at the
  origin
- Test it on a temporary hostname first, end to end
- Cut DNS over in a change window, with a short TTL set the day before
- Verify, then continue from Step 5

**Roll back:** point DNS back. Minutes, plus propagation — which is why the
short TTL matters.

---

## Part 3 · Variants

### 3.1 · Your gateway already has a WAF policy

We do not delete it. The sequence is:

1. Export what is in it — custom rules, exclusions, rule-set version, mode
2. Each existing custom rule gets a decision: **keep** (moves into your band
   70–100 in the new policy), or **drop** (it duplicates a central rule, or
   nobody can say what it is for)
3. Each existing exclusion becomes a dated exception with an owner and a ticket,
   or is dropped
4. The new policy is attached in Detection, and you compare the two logs before
   removing the old one

**Do not skip the comparison.** Running both in parallel for a week is the only
way to know the new policy does not block something the old one allowed.

### 3.2 · Your gateway is shared with other applications

Say so early — this changes the design, not just your plan.

A gateway-level policy applies to every listener that has no policy of its own,
so one exclusion raised for your application would weaken protection for
everyone behind that gateway. Per-listener policies solve that, but each one
then has to carry the full baseline independently, because **scopes do not
combine** — a listener's policy replaces the gateway's rather than adding to it.

We are still working out how the module renders per-listener policies. If you
are on a shared gateway, you are a design conversation, not a standard
onboarding.

### 3.3 · Your origin is not App Service

| Origin | Lockdown |
|---|---|
| AKS | Internal load balancer; NSG permitting the gateway subnet only |
| Container Apps | Internal-only ingress on the environment |
| Function App | Same as App Service, including the SCM site |
| VM / VM scale set | NSG permitting the gateway subnet only |
| Storage static website | Private endpoint with a Front Door Private Link origin |

The sequence is unchanged. Only Step 7 differs.

### 3.4 · You are behind Front Door, not Application Gateway

Mostly the same, with three differences:

- The WAF policy is a **global** resource, but must be in the same subscription
  as the Front Door profile
- Lockdown is a Private Link origin, or the `AzureFrontDoor.Backend` service tag
  **combined with** validation of the `X-Azure-FDID` header against our own
  profile ID. The service tag on its own admits every tenant's Front Door,
  including an attacker's — it is not a lockdown
- Exclusions must name specific rule IDs. An override block with no rules
  disables the entire rule group, which is the opposite of what you wanted

### 3.5 · API Management is involved

APIM has its own gateway, and it is not a WAF. The pattern is Application
Gateway or Front Door **in front of** APIM, with APIM's own endpoint locked
down the same way any other origin is.

If your APIM instance is internet-facing today with nothing in front of it,
treat it as situation **A1** and start at Part 2. The lockdown in Step 7 is
APIM's network configuration rather than App Service access restrictions —
talk to us, because the options differ by APIM tier.

### 3.6 · You need a fixed source IP for a partner

Tell us at Step 0. This is solvable but it constrains the design, and finding
out at Step 7 means redoing work.

---

## Part 4 · When something breaks

**Reverse the step first. Investigate second.** Every step in Part 1 reverses in
minutes, and none of them needs a change advisory board to undo during an
incident.

| Symptom | Most likely | Do |
|---|---|---|
| Application unreachable right after Step 4 | Gateway reconfiguration, or a health probe failing | Check backend health. Remove `firewall_policy_id` if unresolved |
| A partner integration fails after Step 7 | A caller nobody found in Step 6 | Set `ip_restriction_default_action = "Allow"`, re-apply, then add them properly |
| Deployment fails after Step 7 | Something in the pipeline used the SCM hostname directly | Re-open, then move the pipeline to the control plane |
| Real users blocked after Step 9 | A false positive missed in Step 8 | Back to Detection. Find the rule ID in the log, write the exclusion |
| A deployment is refused with "EXPIRED WAF EXCLUSION" | An exception passed its date | Renew with a new ticket and date, or delete it if the application was fixed |
| Plan refuses with "NO BLANKET EXCLUSIONS" | The exclusion names no rule group | Add `rule_group_name` and the specific rule IDs |

---

## Part 5 · What we need from you, and when

| When | What |
|---|---|
| Before Step 0 | A named risk owner — an individual, not a mailbox |
| Step 0 | The gateway inventory, and whether any listener has its own policy |
| Step 1 | Where your gateway is defined |
| Step 6 | Your caller list, and confirmation that you have asked around |
| Step 7 | A change window, and people contactable |
| Step 9 | A change window, and agreement on what "it went wrong" looks like |
| Any time | Anything awkward: partner allowlists, client certificates, fixed source IPs, non-standard ports, shared gateways |

---

## Part 6 · Contacts

| | |
|---|---|
| Day to day | *CCoE WAF channel — to be confirmed* |
| Onboarding lead | *To be confirmed* |
| Production is broken and you think it is the WAF | **Reverse the step first** using Part 4, then tell us. Do not wait for an answer |
| Out of hours | *Escalation path — to be confirmed* |

---

## Appendix · Terms

| | |
|---|---|
| **Detection mode** | The WAF inspects and logs. It blocks nothing |
| **Prevention mode** | The WAF blocks what it judges to be an attack |
| **Managed rule set** | Microsoft's maintained rules, based on OWASP. We set the version; nobody writes these |
| **Anomaly score** | Points per matching rule. Blocked at 5 or more |
| **Exclusion** | Omitting one field from one rule's evaluation, to fix a false positive |
| **Origin** | Your application, behind the gateway |
| **Origin lockdown** | Closing every route to the origin except through the gateway |
| **Per-listener policy** | A WAF policy attached to one listener. It **replaces** the gateway's policy for that traffic |
| **SCM site** | App Service's second hostname. Same application, separate access restrictions |
