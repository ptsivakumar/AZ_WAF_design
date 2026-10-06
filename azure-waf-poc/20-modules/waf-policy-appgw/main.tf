###############################################################################
# WAF policy module — Application Gateway (WAF_v2)
#
# Implements the baseline from the CCoE design plus the reserved priority bands.
# The managed rule set VERSION is an input, not a constant, so the same module
# serves Application Gateway (DRS 2.2) and, later, Application Gateway for
# Containers (DRS 2.1 only).  Runbook step 3.1.
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

locals {
  # Reserved priority bands. Central rules occupy 1-69, application rules 70-100.
  # Application Gateway documents the valid priority range as 1-100 and values
  # must be unique across all custom rules in the policy.
  band_emergency = 1   # 1-9
  band_central   = 10  # 10-39
  band_ratelimit = 40  # 40-69
  band_app       = 70  # 70-100

  # Fail fast if an application rule strays outside its band.
  app_rule_priorities = [for r in var.application_rules : r.priority]
}

resource "azurerm_web_application_firewall_policy" "this" {
  name                = var.name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  # ---------------------------------------------------------------- baseline
  policy_settings {
    enabled                     = true
    mode                        = var.mode # Detection during onboarding, then Prevention
    request_body_check          = true     # mandatory in the baseline
    file_upload_limit_in_mb     = var.file_upload_limit_in_mb
    max_request_body_size_in_kb = var.max_request_body_size_in_kb
  }

  managed_rules {
    # Microsoft Default Rule Set. Version is a variable (see module header).
    managed_rule_set {
      type    = "Microsoft_DefaultRuleSet"
      version = var.managed_ruleset_version

      dynamic "rule_group_override" {
        for_each = var.rule_group_overrides
        content {
          rule_group_name = rule_group_override.value.rule_group_name
          dynamic "rule" {
            for_each = rule_group_override.value.rules
            content {
              id      = rule.value.id
              enabled = rule.value.enabled
              # DRS 2.0+ uses anomaly scoring; per-rule action is Log or AnomalyScoring
              action = rule.value.action
            }
          }
        }
      }
    }

    # Bot Manager. Action per category comes from the workload profile.
    managed_rule_set {
      type    = "Microsoft_BotManagerRuleSet"
      version = var.bot_manager_version
    }

    # ------------------------------------------------------------ exclusions
    # Narrow, attribute-level. Held here in code, never created in the portal.
    # A managed rule set VERSION CHANGE RESETS THESE - the pipeline
    # reconciliation step re-applies them and fails on drift. Runbook step 4.3.
    dynamic "exclusion" {
      for_each = var.exclusions
      content {
        match_variable          = exclusion.value.match_variable
        selector                = exclusion.value.selector
        selector_match_operator = exclusion.value.selector_match_operator
      }
    }
  }

  # ------------------------------------------------- band 40-69: rate limits
  dynamic "custom_rules" {
    for_each = var.rate_limit_rules
    content {
      name      = custom_rules.value.name
      priority  = custom_rules.value.priority
      rule_type = "RateLimitRule"
      action    = "Block" # Allow is not valid on a RateLimitRule
      enabled   = true

      rate_limit_duration  = custom_rules.value.duration  # OneMin | FiveMins
      rate_limit_threshold = custom_rules.value.threshold
      group_rate_limit_by  = custom_rules.value.group_by  # ClientAddr | GeoLocation | None | *XFFHeader

      dynamic "match_conditions" {
        for_each = custom_rules.value.match_conditions
        content {
          match_variables {
            variable_name = match_conditions.value.variable_name
            selector      = lookup(match_conditions.value, "selector", null)
          }
          operator           = match_conditions.value.operator
          negation_condition = lookup(match_conditions.value, "negate", false)
          match_values       = match_conditions.value.match_values
        }
      }
    }
  }

  # --------------------------------------- bands 1-39: central mandatory rules
  dynamic "custom_rules" {
    for_each = var.central_rules
    content {
      name      = custom_rules.value.name
      priority  = custom_rules.value.priority
      rule_type = "MatchRule"
      action    = custom_rules.value.action # Allow | Block | Log | JSChallenge
      enabled   = true

      dynamic "match_conditions" {
        for_each = custom_rules.value.match_conditions
        content {
          match_variables {
            variable_name = match_conditions.value.variable_name
            selector      = lookup(match_conditions.value, "selector", null)
          }
          operator           = match_conditions.value.operator
          negation_condition = lookup(match_conditions.value, "negate", false)
          match_values       = match_conditions.value.match_values
        }
      }
    }
  }

  # ------------------------------------- band 70-100: application team rules
  dynamic "custom_rules" {
    for_each = var.application_rules
    content {
      name      = custom_rules.value.name
      priority  = custom_rules.value.priority
      rule_type = "MatchRule"
      action    = custom_rules.value.action
      enabled   = true

      dynamic "match_conditions" {
        for_each = custom_rules.value.match_conditions
        content {
          match_variables {
            variable_name = match_conditions.value.variable_name
            selector      = lookup(match_conditions.value, "selector", null)
          }
          operator           = match_conditions.value.operator
          negation_condition = lookup(match_conditions.value, "negate", false)
          match_values       = match_conditions.value.match_values
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition = alltrue([
        for p in local.app_rule_priorities : p >= local.band_app && p <= 100
      ])
      error_message = "Application rules must use priority ${local.band_app}-100. Bands 1-69 are reserved for central rules."
    }
    precondition {
      condition     = length(distinct(local.app_rule_priorities)) == length(local.app_rule_priorities)
      error_message = "Custom rule priorities must be unique."
    }
  }
}

# ----------------------------------------------------------------- telemetry
# Baseline requires WAF and firewall logs in the central workspace. In production
# this is deployed by Azure Policy (DeployIfNotExists, control 8); the module sets
# it directly so the PoC can prove both paths.
resource "azurerm_monitor_diagnostic_setting" "this" {
  count = var.log_analytics_workspace_id == null ? 0 : 1

  name                       = "waf-diagnostics"
  target_resource_id         = azurerm_web_application_firewall_policy.this.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log { category_group = "allLogs" }
  metric { category = "AllMetrics" }
}
