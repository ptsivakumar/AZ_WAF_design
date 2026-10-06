variable "prefix" {
  type    = string
  default = "wafpoc"
}

variable "location" {
  type    = string
  default = "westeurope"
}

variable "platform_sub_id" {
  type        = string
  description = "Platform subscription. Mirrors the AWS WAF main account."
}

variable "mgmt_group_id" {
  type        = string
  description = "Full resource ID of the test management group, e.g. /providers/Microsoft.Management/managementGroups/wafpoc"
}

variable "initiative_effect" {
  type        = string
  default     = "Audit"
  description = "Audit for weeks 1-3. Flip to Deny for step 2.4. This single variable is the audit-to-enforce switch."
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.initiative_effect)
    error_message = "initiative_effect must be Audit, Deny or Disabled."
  }
}

variable "builtin_policy_display_names" {
  type        = list(string)
  description = "Microsoft built-ins to include. Confirm each exists before applying - display names occasionally change."
  default = [
    "Azure Web Application Firewall should be enabled for Azure Front Door entry-points",
    "Web Application Firewall (WAF) should be enabled for Application Gateway",
    "Azure Front Door profiles should use Premium tier that supports managed WAF rules and private link",
    "Azure Web Application Firewall on Azure Application Gateway should have request body inspection enabled",
    "Azure Application Gateway should have Resource logs enabled"
  ]
}

variable "tags" {
  type = map(string)
  default = {
    purpose     = "waf-poc"
    owner       = "ccoe"
    disposable  = "true"
  }
}
