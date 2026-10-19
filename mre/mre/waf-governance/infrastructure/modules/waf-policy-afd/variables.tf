variable "name" {
  type        = string
  description = "WAF policy name. Front Door WAF policy names must be alphanumeric only."
  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9]*$", var.name))
    error_message = "Front Door WAF policy names must start with a letter and contain only letters and digits."
  }
}

variable "resource_group_name" {
  type = string
}

variable "cdn_frontdoor_profile_id" {
  type    = string
  default = null
  # Only needed when associated_domain_ids is non-empty, i.e. when this module
  # also creates the security policy binding. workload/main.tf creates its own
  # security policy, so it leaves both of these unset. Required-with-no-default
  # would force every caller to supply a value it never uses.
  description = "Profile the security policy attaches to. MUST be in the same subscription as this WAF policy. Only required when associated_domain_ids is set."
}

variable "associated_domain_ids" {
  type        = list(string)
  default     = []
  description = "Endpoint or custom domain IDs to bind. Empty creates the policy without a security policy."
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "mode" {
  type    = string
  default = "Detection"
  validation {
    condition     = contains(["Detection", "Prevention"], var.mode)
    error_message = "mode must be Detection or Prevention."
  }
}

variable "managed_ruleset_version" {
  type        = string
  default     = "2.1"
  description = <<-EOT
    DEFAULTS TO 2.1, NOT 2.2 — deliberately.
    The provider documents 1.1, 2.0 and 2.1 for Front Door. Microsoft Learn says
    DRS 2.2 is current for Front Door Premium. The provider does not validate,
    so an unsupported value fails at apply.
    Runbook step 4.2 tests 2.2 explicitly. Change this default to "2.2" once that
    test passes, and record the result in the findings report.
  EOT
  validation {
    condition     = contains(["2.0", "2.1", "2.2"], var.managed_ruleset_version)
    error_message = "Permitted values for this PoC: 2.0, 2.1, 2.2."
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

variable "bot_action" {
  type        = string
  default     = "Log"
  description = "Action on the Bot Manager rule set. Profile-driven: Log for web-standard and api-public, Block for critical."
  validation {
    condition     = contains(["Allow", "Log", "Block", "Redirect"], var.bot_action)
    error_message = "bot_action must be Allow, Log, Block or Redirect."
  }
}

variable "rule_group_overrides" {
  type = list(object({
    rule_group_name = string
    rules = list(object({
      id      = string
      enabled = bool
      action  = string # Log or AnomalyScoring on DRS 2.x
    }))
  }))
  default = []
}

variable "exclusions" {
  description = <<-EOT
    Front Door exclusions, scoped to named rule IDs inside a rule group.

    rule_ids is NOT optional, and that is deliberate. azurerm documents that
    an override block containing no rule blocks disables every rule in the
    group. A group-scoped exclusion written the obvious way would therefore
    switch off the group it was meant to narrow. Attaching the exclusion to
    the specific rules that fired avoids the hazard entirely and is more
    precise besides.
  EOT
  type = list(object({
    match_variable  = string
    selector        = string
    operator        = string
    rule_group_name = string
    rule_ids        = list(string)

    # Governance. Validated in the root module, carried here so the exception
    # view can be generated from the same place the control is defined.
    justification = string
    requested_by  = string
    risk_owner    = string
    ticket        = string
    expires       = string
  }))
  default = []
}

variable "central_rules" {
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
}

variable "rate_limit_rules" {
  description = "Front Door counts per socket IP per EDGE SERVER. Baseline uses duration_minutes = 5 with threshold >= 200."
  type = list(object({
    name             = string
    priority         = number
    action           = string # Block | Log | Redirect | (Premium) JSChallenge, CAPTCHA
    duration_minutes = number # 1 or 5
    threshold        = number
    match_conditions = list(object({
      match_variable = string
      selector       = optional(string)
      operator       = string
      negate         = optional(bool, false)
      match_values   = list(string)
    }))
  }))
  default = []
}

variable "application_rules" {
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
}
