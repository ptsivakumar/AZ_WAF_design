###############################################################################
# variables.tf
#
# NO subscription_id. versions.tf configures the provider without one, so the
# subscription comes from the pipeline's credentials. Adding one here would
# let a run target the wrong subscription.
###############################################################################

# ------------------------------------------------------------------ naming
variable "workload" {
  type        = string
  default     = "waf"
  description = "Workload token used in resource names: rg-<location>-<workload>."
}

variable "location" {
  type        = string
  default     = "westeurope"
  description = "Azure region. The WAF policy and the Application Gateway must be in the same region — both derive from this."
}

variable "name_prefix" {
  type        = string
  default     = "ccoe-waf-sbx"
  description = "Prefix for every resource this creates. Matches the names already in sbx."
}

variable "resource_group_name" {
  type        = string
  default     = "ccoe-waf-poc-rg"
  description = "The resource group everything goes into. Already exists in sbx."
}

variable "create_resource_group" {
  type        = bool
  default     = false
  description = "False binds to an existing group of the same name instead of creating it. Terraform does not adopt resources it did not create."
}

variable "tags" {
  type    = map(string)
  default = {}
}

# -----------------------------------------------------------------------------
# ENVIRONMENT — a first-class variable, not just a tag.
#
# Almost every guardrail varies by environment: lockdown is mandatory outside
# sandbox, Detection mode is acceptable in dev and not in production, the
# exception ceiling is 30 days in prd and 90 in dev. None of that can be
# expressed while environment exists only as a string inside var.tags.
#
# The per-environment values live in central-rules.tf, under CODEOWNERS.
# -----------------------------------------------------------------------------
variable "environment" {
  type        = string
  description = "sbx | dev | stag | prd. Drives every guardrail in guardrails.tf."
  validation {
    condition     = contains(["sbx", "dev", "stag", "prd"], var.environment)
    error_message = "environment must be one of: sbx, dev, stag, prd."
  }
}

# -----------------------------------------------------------------------------
# An onboarding waiver for Detection mode outside sbx and dev.
#
# Detection is correct while tuning false positives and wrong as a steady
# state. Rather than forbid it outright — which would make onboarding
# impossible — it is permitted while a dated waiver is live. The waiver
# expiring is what stops "temporarily in Detection" becoming permanent.
#
# Same shape as a WAF exclusion, on purpose: one concept for teams to learn.
# -----------------------------------------------------------------------------
variable "waf_mode_waiver" {
  type = object({
    justification = string
    risk_owner    = string
    ticket        = string
    expires       = string # YYYY-MM-DD
  })
  default     = null
  description = "Permits Detection mode outside sbx/dev until the expiry date. Null means none."
  validation {
    condition     = var.waf_mode_waiver == null || length(trimspace(var.waf_mode_waiver.justification)) >= 30
    error_message = "A mode waiver needs a justification of at least 30 characters — what is being tuned, and when Prevention is expected."
  }
  validation {
    condition     = var.waf_mode_waiver == null || can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[A-Za-z]{2,}$", var.waf_mode_waiver.risk_owner))
    error_message = "waf_mode_waiver.risk_owner must be a named person who accepts running without blocking, not a team alias."
  }
}

variable "application_owner" {
  type        = string
  default     = "ccoe"
  description = "Written to the application-owner tag, which control 06 requires."
}

variable "waf_profile" {
  type        = string
  default     = "web-standard"
  description = "Workload profile: web-standard, api-public or critical. Drives the required-tags control. Set an invalid value to test that control."
}

# --------------------------------------------------------------- toggles
# Front Door Premium and Application Gateway bill by the hour whether used or
# not. Enable one pattern at a time unless you are deliberately comparing them.
variable "enable_appgw" {
  type        = bool
  default     = true
  description = "Pattern B — Application Gateway WAF_v2. Billable."
}

variable "enable_frontdoor" {
  type        = bool
  default     = false
  description = "Pattern A — Front Door Premium. BILLABLE PER HOUR OR PARTIAL HOUR the profile exists. Off by default."
}

variable "create_log_analytics" {
  type        = bool
  default     = true
  description = "Create a workspace. Ignored when log_analytics_workspace_name is set."
}

variable "lockdown_enabled" {
  type = bool
  # DEFAULT CHANGED false -> true. Fail secure.
  #
  # A team that copies this module and forgets to set it used to get an open
  # origin and no warning. Now forgetting it gets you a locked one. The sbx
  # tfvars sets it to false explicitly, so the bypass test still has its
  # unlocked "before" run — but that is now a deliberate act, not a default.
  default     = true
  description = <<-EOT
    Origin lockdown. Set FALSE only to establish the bypass test baseline —
    run unlocked, then flip to true and re-run. A single run proves nothing;
    the pair is the evidence. guardrails.tf refuses false outside sbx.
  EOT
}

# ------------------------------------------------------------ existing bits
variable "log_analytics_workspace_name" {
  type        = string
  default     = null
  description = "Consume an existing workspace instead of creating one."
}

variable "log_analytics_resource_group_name" {
  type        = string
  default     = null
  description = "Resource group of the existing workspace. Required when log_analytics_workspace_name is set."
}

variable "log_retention_days" {
  type        = number
  default     = 30
  description = "PoC value. Production retention is a separate decision."
}

variable "existing_vnet_name" {
  type        = string
  default     = null
  description = "Consume an existing virtual network instead of creating one."
}

variable "existing_vnet_resource_group_name" {
  type    = string
  default = null
}

variable "appgw_subnet_name" {
  type        = string
  default     = null
  description = "Name of the existing Application Gateway subnet. Required when existing_vnet_name is set. The gateway needs a dedicated subnet."
}

variable "vnet_address_space" {
  type        = string
  default     = "10.100.0.0/16"
  description = "Only used when creating a network. Check it does not clash with anything in sbx."
}

variable "appgw_subnet_prefix" {
  type    = string
  default = "10.100.1.0/24"
}

# ------------------------------------------------------------- WAF baseline
variable "waf_mode" {
  type = string
  # DEFAULT CHANGED Detection -> Prevention. Fail secure.
  #
  # Detection is the right setting while onboarding and the wrong one to
  # arrive at by forgetting. A team that sets nothing now blocks; a team that
  # needs to observe first says so, and outside sbx/dev says so with a dated
  # waiver. See guardrails.tf.
  default     = "Prevention"
  description = "Detection during onboarding, then Prevention. Applies to both patterns."
  validation {
    condition     = contains(["Detection", "Prevention"], var.waf_mode)
    error_message = "waf_mode must be Detection or Prevention."
  }
}

variable "appgw_ruleset_version" {
  type        = string
  default     = "2.2"
  description = "azurerm 4.81 documents 2.1 and 2.2 for Application Gateway. 2.2 is the CCoE baseline."
  validation {
    condition     = contains(["2.1", "2.2"], var.appgw_ruleset_version)
    error_message = "Only DRS 2.1 or 2.2 are permitted by the baseline."
  }
}

variable "afd_ruleset_version" {
  type        = string
  default     = "2.1"
  description = <<-EOT
    DEFAULTS TO 2.1, and that is correct for this provider version.
    azurerm 4.81 documents Microsoft_DefaultRuleSet 1.1 / 2.0 / 2.1 for Front
    Door, while Application Gateway gets 2.1 / 2.2. The asymmetry is real at
    the provider level, not an oversight.
  EOT
  validation {
    condition     = contains(["1.1", "2.0", "2.1"], var.afd_ruleset_version)
    error_message = "azurerm 4.81 documents 1.1, 2.0 or 2.1 for Front Door."
  }
}

variable "bot_manager_version" {
  type    = string
  default = "1.1"
  validation {
    condition     = contains(["1.0", "1.1"], var.bot_manager_version)
    error_message = "Bot Manager Rule Set version must be 1.0 or 1.1."
  }
}

# --------------------------------------------------------------- sizing
variable "app_service_sku" {
  type        = string
  default     = "B1"
  description = "B1 is adequate. Access restrictions are available on all paid tiers. F1 is free but disables always_on."
}

variable "appgw_min_capacity" {
  type = number
  # NULL means "use the environment's minimum" from central-rules.tf — 1 in
  # sbx and dev, 2 in stag and prd. A team that says nothing gets the right
  # answer for where it is deploying; a team that sets something lower is
  # refused by guardrails.tf. Setting something higher is always fine.
  default     = null
  description = "Gateway autoscale minimum. Null uses the environment baseline. Below the baseline fails the plan — rate limits are counted per instance."
}

variable "appgw_max_capacity" {
  type    = number
  default = 2
}

###############################################################################
# RULES AND EXCLUSIONS — what an application team may and may not set.
#
# Central rules are NOT variables. They live in central-rules.tf, under
# CODEOWNERS, so a pull request cannot change them without security approval.
# Nothing an application team writes in workload.tfvars can add, reorder or
# remove a central rule. That is the point.
#
# What an application team CAN set is below: rules in band 70-100, and
# exclusions that carry a justification, an owner, a ticket and an expiry date.
#
# The validation blocks here run during plan — about fifteen seconds into the
# pipeline, before a single Azure resource is touched. A rule in the wrong band
# or an exclusion with no expiry fails the pull request, not the review.
###############################################################################

# ----------------------------------------- band 70-100: application rules
variable "appgw_application_rules" {
  description = "Application Gateway custom rules owned by the application team. Priority 70-100 only."
  type = list(object({
    name     = string
    priority = number
    action   = string
    match_conditions = list(object({
      variable_name = string
      selector      = optional(string)
      operator      = string
      negate        = optional(bool, false)
      match_values  = list(string)
    }))
  }))
  default = []

  validation {
    condition     = alltrue([for r in var.appgw_application_rules : r.priority >= 70 && r.priority <= 100])
    error_message = "Application rules must use priority 70-100. Bands 1-69 belong to security (1-9 emergency, 10-39 central, 40-69 rate limits) and are defined in central-rules.tf."
  }
  validation {
    condition     = length(distinct([for r in var.appgw_application_rules : r.priority])) == length(var.appgw_application_rules)
    error_message = "Custom rule priorities must be unique within a policy."
  }
  validation {
    condition     = alltrue([for r in var.appgw_application_rules : contains(["Allow", "Block", "Log", "JSChallenge"], r.action)])
    error_message = "action must be Allow, Block, Log or JSChallenge."
  }
}

variable "afd_application_rules" {
  description = "Front Door custom rules owned by the application team. Priority 70-100 only. Uses match_variable, not variable_name."
  type = list(object({
    name     = string
    priority = number
    action   = string
    match_conditions = list(object({
      match_variable = string
      selector       = optional(string)
      operator       = string
      negate         = optional(bool, false)
      match_values   = list(string)
    }))
  }))
  default = []

  validation {
    condition     = alltrue([for r in var.afd_application_rules : r.priority >= 70 && r.priority <= 100])
    error_message = "Application rules must use priority 70-100. Bands 1-69 belong to security and are defined in central-rules.tf."
  }
  validation {
    condition     = length(distinct([for r in var.afd_application_rules : r.priority])) == length(var.afd_application_rules)
    error_message = "Custom rule priorities must be unique within a policy."
  }
}

variable "afd_bot_action" {
  type        = string
  default     = "Log"
  description = "Bot Manager action on Front Door. Profile-driven: Log for web-standard and api-public, Block for critical."
  validation {
    condition     = contains(["Allow", "Log", "Block", "Redirect"], var.afd_bot_action)
    error_message = "afd_bot_action must be Allow, Log, Block or Redirect."
  }
}

###############################################################################
# EXCLUSIONS — the exception flow.
#
# An exclusion tells the WAF to ignore part of a request when evaluating
# managed rules. It is the correct fix for a false positive and the most
# common way a WAF is silently switched off. Four properties separate the two:
#
#   SCOPED       it names the rule group it applies to. An exclusion with no
#                scope applies to every managed rule in the policy, which is
#                most of the WAF.
#   JUSTIFIED    a sentence a reviewer who was not in the conversation can
#                read in six months and understand.
#   OWNED        a person, not a team alias. Teams do not answer questions.
#   TEMPORARY    an expiry date. The plan fails once it passes, so the default
#                outcome of forgetting about an exclusion is that it is
#                removed, not that it lives forever.
#
# All four are enforced below and in exceptions.tf. None of them require the
# WAF to exist — they are checked at plan time.
#
# A NOTE ON SCOPE, BECAUSE THE TWO PLATFORMS DIFFER
#
# Application Gateway scopes an exclusion with excluded_rule_set -> rule_group,
# and can narrow further to specific rule IDs.
# Front Door has no such field. Scope comes from WHERE the exclusion sits: at
# managed_rule level it is policy-wide, nested inside an override it applies to
# that rule group only. So rule_group_name is required on both, but
# excluded_rules is Application Gateway only.
###############################################################################

variable "appgw_exclusions" {
  description = <<-EOT
    Application Gateway exclusions. Populated from a real false positive seen
    in Detection mode, never guessed in advance.

    match_variable (azurerm 4.81): RequestArgKeys, RequestArgNames,
    RequestArgValues, RequestCookieKeys, RequestCookieNames,
    RequestCookieValues, RequestHeaderKeys, RequestHeaderNames,
    RequestHeaderValues.

    There is no JSON body selector here. Front Door has RequestBodyJsonArgNames
    and Application Gateway does not, so a false positive on a JSON body field
    is tunable on Pattern A and may not be on Pattern B. Worth knowing before
    promising an application team a fix.
  EOT
  type = list(object({
    match_variable  = string
    selector        = string
    operator        = string
    rule_group_name = string
    excluded_rules  = optional(list(string), []) # empty = the whole rule group

    justification = string
    requested_by  = string # the engineer who raised it
    risk_owner    = string # the application owner who ACCEPTS the residual risk
    ticket        = string
    expires       = string # YYYY-MM-DD
  }))
  default = []

  validation {
    condition = alltrue([for e in var.appgw_exclusions : contains([
      "RequestArgKeys", "RequestArgNames", "RequestArgValues",
      "RequestCookieKeys", "RequestCookieNames", "RequestCookieValues",
      "RequestHeaderKeys", "RequestHeaderNames", "RequestHeaderValues",
    ], e.match_variable)])
    error_message = "match_variable is not one of the values azurerm 4.81 documents for an Application Gateway exclusion. RequestBodyJsonArgNames is Front Door only."
  }
  validation {
    condition     = alltrue([for e in var.appgw_exclusions : contains(["Contains", "EndsWith", "Equals", "EqualsAny", "StartsWith"], e.operator)])
    error_message = "operator must be Contains, EndsWith, Equals, EqualsAny or StartsWith."
  }
  validation {
    condition     = alltrue([for e in var.appgw_exclusions : trimspace(e.rule_group_name) != ""])
    error_message = "NO BLANKET EXCLUSIONS. Every exclusion must name the rule group it applies to, for example REQUEST-942-APPLICATION-ATTACK-SQLI. An unscoped exclusion disables the field across every managed rule in the policy."
  }
  validation {
    condition     = alltrue([for e in var.appgw_exclusions : length(trimspace(e.justification)) >= 30])
    error_message = "Every exclusion needs a justification of at least 30 characters: what the false positive was, and why excluding this field is safe. 'false positive' is not a justification."
  }
  validation {
    condition     = alltrue([for e in var.appgw_exclusions : can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[A-Za-z]{2,}$", e.requested_by))])
    error_message = "requested_by must be the email address of the engineer raising this exclusion."
  }
  validation {
    condition     = alltrue([for e in var.appgw_exclusions : can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[A-Za-z]{2,}$", e.risk_owner))])
    error_message = "risk_owner must be a named person who can accept residual risk for this application — not a team alias and not the engineer who wrote the Terraform. Teams do not answer questions in six months."
  }
  # KNOWN GAP, STATED DELIBERATELY.
  #
  # This checks the SHAPE of the ticket reference, not its EXISTENCE. SEC-9999
  # passes whether or not such a record was ever raised. At pilot scale the
  # ticket buys traceability, not control.
  #
  # Closing it means calling the exception system's API from the pipeline and
  # refusing to merge unless the record exists, is approved, and carries the
  # same expiry date as the code. That is a known, scoped piece of work — it
  # is not done, and nobody should describe this check as if it were.
  validation {
    condition     = alltrue([for e in var.appgw_exclusions : can(regex("^[A-Z][A-Z0-9]*-[0-9]+$", e.ticket))])
    error_message = "ticket must reference a change or exception record, for example SEC-1234."
  }
  validation {
    condition     = alltrue([for e in var.appgw_exclusions : can(regex("^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$", e.expires))])
    error_message = "expires must be a date as YYYY-MM-DD. Exclusions are temporary by default; exceptions.tf fails the plan once the date passes."
  }
}

variable "afd_exclusions" {
  description = <<-EOT
    Front Door exclusions. Same governance fields as Application Gateway.

    match_variable: QueryStringArgNames, RequestBodyPostArgNames,
    RequestCookieNames, RequestHeaderNames, RequestBodyJsonArgNames.

    rule_ids IS REQUIRED HERE AND OPTIONAL ON APPLICATION GATEWAY.

    Front Door has no scope field. An exclusion is scoped by where it sits:
    at managed_rule level it applies to the whole rule set, nested in an
    override it applies to that group, nested in a rule it applies to that
    rule. The obvious middle option is a trap — azurerm documents that an
    override block with no rule blocks DISABLES EVERY RULE IN THE GROUP. An
    exclusion written that way would turn off far more than it excluded.

    So on Front Door an exclusion must name the rule IDs that actually fired.
    You read them out of the Detection-mode logs, which is the right habit
    anyway: exclude the rule that false-positived, not the group it lives in.
  EOT
  type = list(object({
    match_variable  = string
    selector        = string
    operator        = string
    rule_group_name = string
    rule_ids        = list(string)

    justification = string
    requested_by  = string # the engineer who raised it
    risk_owner    = string # the application owner who ACCEPTS the residual risk
    ticket        = string
    expires       = string # YYYY-MM-DD
  }))
  default = []

  validation {
    condition     = alltrue([for e in var.afd_exclusions : length(e.rule_ids) > 0])
    error_message = "rule_ids cannot be empty on a Front Door exclusion. An override with no rules disables the whole rule group, so a group-level exclusion here would switch off far more than it excludes. Name the rule IDs from the Detection-mode logs, for example [\"942100\"]."
  }

  validation {
    condition = alltrue([for e in var.afd_exclusions : contains([
      "QueryStringArgNames", "RequestBodyPostArgNames", "RequestCookieNames",
      "RequestHeaderNames", "RequestBodyJsonArgNames",
    ], e.match_variable)])
    error_message = "match_variable is not one of the values azurerm 4.81 documents for a Front Door exclusion."
  }
  validation {
    condition     = alltrue([for e in var.afd_exclusions : contains(["Contains", "EndsWith", "Equals", "EqualsAny", "StartsWith"], e.operator)])
    error_message = "operator must be Contains, EndsWith, Equals, EqualsAny or StartsWith."
  }
  validation {
    condition     = alltrue([for e in var.afd_exclusions : e.operator != "EqualsAny" || e.selector == "*"])
    error_message = "Front Door requires selector = \"*\" when operator is EqualsAny."
  }
  validation {
    condition     = alltrue([for e in var.afd_exclusions : trimspace(e.rule_group_name) != ""])
    error_message = "NO BLANKET EXCLUSIONS. Every exclusion must name the rule group it applies to. On Front Door an unscoped exclusion sits at managed_rule level and applies to the entire rule set."
  }
  validation {
    condition     = alltrue([for e in var.afd_exclusions : length(trimspace(e.justification)) >= 30])
    error_message = "Every exclusion needs a justification of at least 30 characters: what the false positive was, and why excluding this field is safe."
  }
  validation {
    condition     = alltrue([for e in var.afd_exclusions : can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[A-Za-z]{2,}$", e.requested_by))])
    error_message = "requested_by must be the email address of the engineer raising this exclusion."
  }
  validation {
    condition     = alltrue([for e in var.afd_exclusions : can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[A-Za-z]{2,}$", e.risk_owner))])
    error_message = "risk_owner must be a named person who can accept residual risk for this application — not a team alias and not the engineer who wrote the Terraform."
  }
  validation {
    condition     = alltrue([for e in var.afd_exclusions : can(regex("^[A-Z][A-Z0-9]*-[0-9]+$", e.ticket))])
    error_message = "ticket must reference a change or exception record, for example SEC-1234."
  }
  validation {
    condition     = alltrue([for e in var.afd_exclusions : can(regex("^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$", e.expires))])
    error_message = "expires must be a date as YYYY-MM-DD."
  }
}

# ------------------------------------------------------- exception lifetime
variable "max_exception_days" {
  description = "Longest life an exclusion may be granted at creation. A year is not an exception, it is a decision nobody made."
  type        = number
  default     = 90
  validation {
    condition     = var.max_exception_days > 0 && var.max_exception_days <= 365
    error_message = "max_exception_days must be between 1 and 365."
  }
}
