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
  type        = bool
  default     = false
  description = <<-EOT
    Origin lockdown. FALSE for the first apply, deliberately — run the bypass
    test unlocked to establish the baseline, then flip to true and re-run.
    A single run proves nothing; the pair is the evidence.
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
  type        = string
  default     = "Detection"
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
  type    = number
  default = 1
}

variable "appgw_max_capacity" {
  type    = number
  default = 2
}

# ----------------------------------------------------- rules and exclusions
# Priority bands, enforced by a precondition in the module:
#   1-9    emergency virtual patch   (CCoE)
#   10-39  mandatory central rules   (CCoE)
#   40-69  rate limits               (CCoE)
#   70-100 application team rules    (app team, security approved)
variable "appgw_central_rules" {
  description = "Application Gateway, bands 1-39. CCoE-owned. Uses variable_name in match_conditions."
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

variable "appgw_rate_limit_rules" {
  description = "Application Gateway, band 40-69. duration is FiveMins or OneMin; thresholds are per gateway INSTANCE."
  type = list(object({
    name      = string
    priority  = number
    duration  = string
    threshold = number
    group_by  = string
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

variable "appgw_application_rules" {
  type        = list(any)
  default     = []
  description = "Application Gateway, band 70-100. A priority below 70 fails the plan — that precondition is itself a test."
}

# ---------------------------------------------------------------------------
# Front Door takes the SAME CONCEPTS with DIFFERENT FIELD NAMES:
#   match_variable        not variable_name
#   duration_minutes (1|5) not duration ("OneMin"|"FiveMins")
#   no group_by — Front Door counts per socket IP per edge server
# Kept as separate variables so the difference is visible rather than
# discovered at apply. Exact shapes are in modules/waf-policy-afd/variables.tf.
# ---------------------------------------------------------------------------
variable "afd_central_rules" {
  type    = list(any)
  default = []
}

variable "afd_rate_limit_rules" {
  type    = list(any)
  default = []
}

variable "afd_application_rules" {
  type    = list(any)
  default = []
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

variable "appgw_exclusions" {
  type = list(object({
    match_variable          = string
    selector                = string
    selector_match_operator = string
  }))
  default     = []
  description = <<-EOT
    Populated from a real false positive seen in Detection mode, not guessed.
    azurerm 4.81 documents these match_variable values for Application Gateway:
    RequestArgKeys/Names/Values, RequestCookieKeys/Names/Values,
    RequestHeaderKeys/Names/Values.
    JSON body selectors are NOT in that list for Application Gateway — but they
    ARE for Front Door (RequestBodyJsonArgNames). A JSON-body false positive is
    therefore tunable on Pattern A and may not be on Pattern B. Worth knowing
    before promising an app team a fix.
  EOT
}

variable "afd_exclusions" {
  type = list(object({
    match_variable          = string
    selector                = string
    selector_match_operator = string
  }))
  default     = []
  description = "Front Door exclusions. match_variable accepts QueryStringArgNames, RequestBodyPostArgNames, RequestCookieNames, RequestHeaderNames and RequestBodyJsonArgNames."
}
