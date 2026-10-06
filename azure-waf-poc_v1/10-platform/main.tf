###############################################################################
# 10-platform — Log Analytics, custom policy definitions, initiative, assignment
#
# TWO CORRECTIONS vs. older examples you will find online:
#
#  1. azurerm_policy_set_definition NO LONGER has management_group_id in
#     provider v5. Use azurerm_management_group_policy_set_definition.
#     Plain azurerm_policy_definition DOES still take management_group_id —
#     there is no azurerm_management_group_policy_definition resource.
#
#  2. The assignment needs an identity and a location because the initiative
#     contains a DeployIfNotExists effect (diagnostic settings, control 8).
#
# Runbook steps 2.1 to 2.4.
###############################################################################

terraform {
  required_version = ">= 1.9"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 5.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.platform_sub_id
}

resource "azurerm_resource_group" "platform" {
  name     = "${var.prefix}-platform-rg"
  location = var.location
  tags     = var.tags
}

# ------------------------------------------------------------- telemetry
resource "azurerm_log_analytics_workspace" "central" {
  name                = "${var.prefix}-law"
  resource_group_name = azurerm_resource_group.platform.name
  location            = azurerm_resource_group.platform.location
  sku                 = "PerGB2018"
  retention_in_days   = 30 # PoC only. Production retention is a separate decision.
  tags                = var.tags
}

# ---------------------------------------------- custom policy definitions
# Stored at the MANAGEMENT GROUP, not in a subscription. A definition can only
# be assigned at or below where it is stored, so a definition in a subscription
# could never be assigned across the landing zones.
locals {
  policy_files = fileset("${path.module}/policies", "*.json")

  policies = {
    for f in local.policy_files :
    trimsuffix(f, ".json") => jsondecode(file("${path.module}/policies/${f}"))
  }
}

resource "azurerm_policy_definition" "custom" {
  for_each = local.policies

  name                = each.key
  policy_type         = "Custom"
  mode                = lookup(each.value, "mode", "Indexed")
  display_name        = each.value.displayName
  description         = lookup(each.value, "description", null)
  management_group_id = var.mgmt_group_id

  policy_rule = jsonencode(each.value.policyRule)
  parameters  = jsonencode(lookup(each.value, "parameters", {}))

  metadata = jsonencode({
    category = "WAF"
    version  = "1.0.0"
    source   = "CCoE Azure WAF PoC"
  })
}

# --------------------------------------------------- built-in definitions
# Microsoft ships built-ins for several controls. Prefer them over custom.
# These IDs are stable, but confirm with:
#   az policy definition list --query "[?contains(displayName,'Web Application Firewall')].{name:name,display:displayName}" -o table
data "azurerm_policy_definition" "builtin" {
  for_each     = toset(var.builtin_policy_display_names)
  display_name = each.value
}

# ---------------------------------------------------------- the initiative
resource "azurerm_management_group_policy_set_definition" "waf" {
  name                = "${var.prefix}-waf-initiative"
  policy_type         = "Custom"
  display_name        = "Azure WAF guardrails — CCoE PoC"
  description         = "Thirteen controls covering ingress, baseline, origin lockdown and tagging. Audit in months 1-3, Deny in months 4-6."
  management_group_id = var.mgmt_group_id

  metadata = jsonencode({ category = "WAF", version = "1.0.0" })

  # One shared effect parameter so the whole initiative flips Audit -> Deny
  # in a single change, which is what the runbook step 2.4 exercises.
  parameters = jsonencode({
    effect = {
      type         = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue = "Audit"
      metadata     = { displayName = "Effect for custom controls" }
    }
  })

  dynamic "policy_definition_reference" {
    for_each = azurerm_policy_definition.custom
    content {
      policy_definition_id = policy_definition_reference.value.id
      reference_id         = policy_definition_reference.key
      parameter_values = jsonencode({
        effect = { value = "[parameters('effect')]" }
      })
    }
  }

  dynamic "policy_definition_reference" {
    for_each = data.azurerm_policy_definition.builtin
    content {
      policy_definition_id = policy_definition_reference.value.id
      reference_id         = replace(policy_definition_reference.key, " ", "-")
    }
  }
}

# ----------------------------------------------------------- assignment
resource "azurerm_management_group_policy_assignment" "waf" {
  # Assignment name is limited to 24 characters.
  name                 = substr("${var.prefix}-waf-assign", 0, 24)
  display_name         = "Azure WAF guardrails (PoC)"
  management_group_id  = var.mgmt_group_id
  policy_definition_id = azurerm_management_group_policy_set_definition.waf.id

  # Required because the initiative contains DeployIfNotExists.
  location = var.location
  identity {
    type = "SystemAssigned"
  }

  enforce = true

  parameters = jsonencode({
    effect = { value = var.initiative_effect }
  })

  non_compliance_message {
    content = "This resource does not meet the CCoE Azure WAF baseline. See the WAF design proposal, section 7."
  }
}

# The remediation identity needs permission to create diagnostic settings.
# Contributor is broader than ideal; narrow before production.
resource "azurerm_role_assignment" "remediation" {
  scope                = var.mgmt_group_id
  role_definition_name = "Contributor"
  principal_id         = azurerm_management_group_policy_assignment.waf.identity[0].principal_id
}
