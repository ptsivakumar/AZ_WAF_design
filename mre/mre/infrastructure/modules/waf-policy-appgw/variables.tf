variable "name" {
  type        = string
  description = "WAF policy name."
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type        = string
  description = "MUST match the Application Gateway's region. A WAF policy can only be associated with a gateway in the same region and subscription."
}

variable "tags" {
  type    = map(string)
  default = {}
}

# --------------------------------------------------------------- baseline
variable "mode" {
  type        = string
  default     = "Detection"
  description = "Detection during the 30-day onboarding window, then Prevention."
  validation {
    condition     = contains(["Detection", "Prevention"], var.mode)
    error_message = "mode must be Detection or Prevention."
  }
}

variable "managed_ruleset_version" {
  type        = string
  default     = "2.2"
  description = <<-EOT
    Microsoft Default Rule Set version.
    "2.2" is the CCoE baseline and is documented for Application Gateway.
    "2.1" is the only version supported by Application Gateway for Containers,
    and is the fallback if 2.2 proves unavailable on a platform.
    This is an input precisely so AGC becomes a variant later, not a rewrite.
  EOT
  validation {
    condition     = contains(["2.1", "2.2"], var.managed_ruleset_version)
    error_message = "Only DRS 2.1 or 2.2 are permitted by the CCoE baseline."
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

variable "file_upload_limit_in_mb" {
  type    = number
  default = 100
}

variable "max_request_body_size_in_kb" {
  type    = number
  default = 128
}

variable "log_analytics_workspace_id" {
  type        = string
  default     = null
  description = "Set to send WAF diagnostics to the central workspace. Null leaves it to Azure Policy DeployIfNotExists."
}

# --------------------------------------------------------------- overrides
variable "rule_group_overrides" {
  description = "Managed rule group overrides. Use sparingly; prefer exclusions."
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
    Managed-rule exclusions. Narrow and attribute-level.
    Held here so a rule set version change can be reconciled by pipeline -
    a version change RESETS exclusions to the new set's defaults.
  EOT
  type = list(object({
    match_variable          = string # e.g. RequestBodyJsonArgNames
    selector                = string # e.g. queryExpression
    selector_match_operator = string # Equals | Contains | StartsWith | EndsWith | EqualsAny
  }))
  default = []
}

# -------------------------------------------------------- priority bands
variable "central_rules" {
  description = "Bands 1-39. Emergency virtual patch (1-9) and mandatory central rules (10-39). CCoE-owned."
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
}

variable "rate_limit_rules" {
  description = "Band 40-69. Central rate-limit templates. Thresholds are per gateway INSTANCE, not gateway-wide."
  type = list(object({
    name      = string
    priority  = number
    duration  = string # OneMin | FiveMins - the baseline standardises on FiveMins
    threshold = number
    group_by  = string # ClientAddr | GeoLocation | None | ClientAddrXFFHeader | GeoLocationXFFHeader
    match_conditions = list(object({
      variable_name = string
      selector      = optional(string)
      operator      = string
      negate        = optional(bool, false)
      match_values  = list(string)
    }))
  }))
  default = []
}

variable "application_rules" {
  description = "Band 70-100. Application-team owned, security-approved. Enforced by precondition."
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
}
