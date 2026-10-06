variable "prefix"            { type = string
                               default = "wafpoc" }
variable "location"          { type = string
                               default = "westeurope" }
variable "workload_sub_id"   { type = string }

variable "log_analytics_workspace_id" {
  type        = string
  default     = null
  description = "Output of the 10-platform layer."
}

variable "waf_mode" {
  type        = string
  default     = "Detection"
  description = "Detection for weeks 3-4, Prevention from step 4.5."
}

variable "appgw_ruleset_version" {
  type        = string
  default     = "2.2"
  description = "DRS 2.2 is documented for Application Gateway."
}

variable "afd_ruleset_version" {
  type        = string
  default     = "2.1"
  description = <<-EOT
    DEFAULTS TO 2.1 for Front Door. Step 4.2 tests whether 2.2 applies.
    If it does, change this to "2.2" and record the result. If it fails,
    the finding is that the Front Door baseline must stay on 2.1 - which
    would be a change to the design proposal, section 5.1.
  EOT
}

variable "bot_action" {
  type        = string
  default     = "Log"
  description = "Profile-driven. web-standard and api-public log Unknown bots; critical challenges them."
}

variable "waf_profile" {
  type        = string
  default     = "web-standard"
  description = "Drives the required-tags control. Set to an invalid value to test control 10."
}

variable "application_owner" {
  type    = string
  default = "ccoe-poc"
}

variable "lockdown_enabled" {
  type        = bool
  default     = false
  description = "FALSE for the first apply. Step 4.1 runs the bypass test unlocked, then flips this to true and re-runs."
}

variable "app_service_sku" {
  type        = string
  default     = "B1"
  description = "B1 is adequate. Access restrictions are available on all paid tiers."
}

variable "application_rules" {
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
  default     = []
  description = "Band 70-100 only. Set a priority below 70 to prove the precondition fires (step 3.4)."
}

variable "exclusions" {
  type = list(object({
    match_variable          = string
    selector                = string
    selector_match_operator = string
  }))
  default     = []
  description = "Populated at step 4.4 from a real false positive observed in Detection mode."
}

variable "tags" {
  type = map(string)
  default = {
    purpose    = "waf-poc"
    disposable = "true"
  }
}
