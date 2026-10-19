# =============================================================================
# sbx — Azure WAF workload
#
# No subscription_id and no tenant_id here. versions.tf configures the provider
# without one, so the subscription comes from the pipeline's credentials, and
# the backend ids live in workload.tfbackend.
#
# Run order — one change per run, so every result has a before and an after:
#   1. as below                                    baseline, Pattern B, unlocked
#   2. lockdown_enabled = true                     the bypass test proof
#   3. waf_mode = "Prevention"                     after tuning
#   4. enable_frontdoor = true                     Pattern A  (BILLABLE PER HOUR)
# =============================================================================

workload    = "waf"
location    = "westeurope"
name_prefix = "ccoe-waf-sbx" # matches the existing ccoe-waf-sbx-appgw

# DRIVES EVERY GUARDRAIL. sbx | dev | stag | prd — see guardrails.tf.
#
# sbx is the only environment that may run with the origin unlocked (so the
# bypass test can produce its "before" evidence) and the only one that may
# use a non-baseline rule set version for testing. Change this to "dev" and
# the plan will refuse until lockdown_enabled = true.
environment = "sbx"

# ----------------------------------------------------------------- toggles
#
# PHASE 1 (now): both false. Terraform creates ONLY the App Service origin and
# Log Analytics. Your hand-built ccoe-waf-sbx-appgw is untouched, nothing is
# destroyed, and the first apply takes about two minutes instead of twenty-five.
# The point of run 1 is to learn the pipeline, not to build the gateway.
#
# PHASE 2: enable_appgw = true. Terraform builds its OWN gateway, named
# ccoe-waf-sbx-appgw-tf so it cannot clash with yours. Two WAF_v2 gateways
# cost roughly EUR 10-12 a day extra — fine for days, not for a month.
#
# PHASE 3: once Terraform's gateway works, delete the hand-built one.
enable_appgw     = false
enable_frontdoor = false # Front Door Premium bills per hour or partial hour.

# CONFIRMED IN THE PORTAL — these already exist, so Terraform consumes them
# rather than creating them. Terraform never adopts resources it did not make.
resource_group_name               = "ccoe-waf-poc-rg"
create_resource_group             = false
existing_vnet_name                = "ccoe-waf-poc-vnet" # 10.0.0.0/16
existing_vnet_resource_group_name = "ccoe-waf-poc-rg"
appgw_subnet_name                 = "appgw-subnet" # 10.0.1.0/24, no NSG

create_log_analytics = true

# Step 2 flips this to true. Leave false for the first apply — the unlocked
# bypass test is the baseline half of the evidence.
lockdown_enabled = false

# ------------------------------------------------------------- WAF baseline
waf_mode              = "Detection"
appgw_ruleset_version = "2.2" # documented for Application Gateway on azurerm 4.81
afd_ruleset_version   = "2.1" # 2.2 is NOT documented for Front Door on 4.81
bot_manager_version   = "1.1"

# --------------------------------------------------------------- sizing
app_service_sku    = "B1"
appgw_min_capacity = 1
appgw_max_capacity = 2

# Network values are not needed — the existing vnet and subnet are consumed
# above. vnet_address_space / appgw_subnet_prefix are only used when Terraform
# creates its own network, which it will not here.
#
# If a Log Analytics workspace already exists, add these and set
# create_log_analytics = false:
# log_analytics_workspace_name      = "..."
# log_analytics_resource_group_name = "..."

# -------------------------------------------------------------------- tags
application_owner = "ccoe"
waf_profile       = "web-standard"

# environment and waf-baseline-version are added automatically in locals.tf —
# do not repeat them here.
tags = {
  purpose    = "waf-poc"
  disposable = "true"
}

###############################################################################
# RULES AND EXCLUSIONS — what THIS APPLICATION TEAM owns.
#
# There is no appgw_central_rules here, and no afd_central_rules. The central
# rules live in workload/central-rules.tf under CODEOWNERS, so nothing written
# in this file can add, reorder or remove one. That is the control.
#
# What is below is the application team's half: rules in band 70-100, and
# exclusions that carry a scope, a justification, an owner, a ticket and an
# expiry date. Each of those is checked during plan, before any Azure resource
# is touched.
###############################################################################

afd_bot_action = "Log" # Block for the critical profile

# How long an exclusion may be granted for at creation.
max_exception_days = 90

# ------------------------------------------- band 70-100: application rules
appgw_application_rules = [
  {
    name     = "logLegacyApiVersion"
    priority = 70
    action   = "Log" # Log first. Block once the callers have moved.
    match_conditions = [
      {
        variable_name = "RequestUri"
        operator      = "BeginsWith"
        match_values  = ["/api/v1/"]
      },
    ]
  },
]

# ---------------------------------------------------------------- exclusions
# ONE WORKED EXAMPLE, from a false positive of the kind Detection mode
# actually produces: a search filter containing the word "or" trips the
# restricted-SQL-character rule.
#
# Note what it does NOT do. It does not exclude RequestArgNames globally, and
# it does not exclude the whole SQLI group. It names one field and one rule.
# Everything else in REQUEST-942 still inspects that request.
appgw_exclusions = [
  {
    match_variable  = "RequestArgNames"
    selector        = "filter"
    operator        = "Equals"
    rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
    excluded_rules  = ["942430"] # restricted SQL character anomaly detection

    justification = "Catalogue search sends boolean filter expressions such as 'type eq book or type eq journal'. Rule 942430 counts the special characters as SQL. Confirmed in Detection mode over 3 days, no true positives on this field."

    # TWO NAMES, ON PURPOSE. The engineer who raises an exclusion is rarely
    # the person who can accept the risk of having it. Security sets the
    # guardrails; the application owner accepts what is left inside them.
    requested_by = "ptsivakumar.uk@gmail.com"
    risk_owner   = "application.owner@example.com"

    ticket  = "SEC-1001"
    expires = "2026-12-15"
  },
]

# ---------------------------------------------------------------- Front Door
# Empty while enable_frontdoor = false. Front Door exclusions additionally
# require rule_ids — see the note in workload/variables.tf for why.
afd_application_rules = []
afd_exclusions        = []

###############################################################################
# DEMO — four ways to make the pipeline refuse this file.
#
# Uncomment one at a time, push, and watch the plan fail in about fifteen
# seconds with a readable message. No Azure resource is created or touched by
# any of them.
#
# 1. A rule in a band the application team does not own
#
#    Change the priority above from 70 to 20 and the plan stops with:
#      "Application rules must use priority 70-100. Bands 1-69 belong to
#       security (1-9 emergency, 10-39 central, 40-69 rate limits) and are
#       defined in central-rules.tf."
#
# 2. A blanket exclusion
#
#    Change rule_group_name to "" and the plan stops with:
#      "NO BLANKET EXCLUSIONS. Every exclusion must name the rule group it
#       applies to ..."
#
# 3. An exclusion nobody owns or justified
#
#    Change justification to "false positive" and the plan stops with:
#      "Every exclusion needs a justification of at least 30 characters ...
#       'false positive' is not a justification."
#    Change risk_owner to "cloud-team" and it stops on that instead:
#      "risk_owner must be a named person who can accept residual risk for
#       this application — not a team alias ..."
#
# 4. An exclusion that outlived its exception
#
#    Change expires to "2026-01-01" and the plan stops with:
#      "EXPIRED WAF EXCLUSION — this plan is blocked."
#    Change it to "2027-12-31" and it stops on the 90-day limit instead.
#
# The last one is the one worth dwelling on. Nobody has to remember to review
# this exclusion. The next time anyone plans this workload after 15 December,
# the pipeline raises it. The default outcome of forgetting is removal, not
# permanence.
###############################################################################
