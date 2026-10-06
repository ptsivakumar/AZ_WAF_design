variable "subscription_id" {
  type = string
}

variable "policy_assignment_id" {
  type        = string
  description = "The WAF initiative assignment. Output assignment_id from 10-platform."
}

# --- declared so the shared ../sandbox.tfvars applies cleanly to every layer.
# This layer creates no resource group of its own; exemptions attach to
# resources that already exist.
variable "prefix" {
  type    = string
  default = "wafpoc"
}

variable "location" {
  type    = string
  default = "westeurope"
}

variable "resource_group_name" {
  type    = string
  default = "ccoe-waf-poc-rg"
}

variable "create_resource_group" {
  type    = bool
  default = false
}

variable "tags" {
  type    = map(string)
  default = {}
}
