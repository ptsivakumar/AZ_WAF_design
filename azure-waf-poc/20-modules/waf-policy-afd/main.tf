###############################################################################
# WAF policy module — Azure Front Door Premium
#
# IMPORTANT (runbook step 4.2):
#   The AzureRM provider documents only 1.1, 2.0 and 2.1 for
#   Microsoft_DefaultRuleSet on azurerm_cdn_frontdoor_firewall_policy, while
#   Microsoft Learn states DRS 2.2 is current for Front Door Premium.
#   The provider does NOT validate the string — it is sent verbatim to the API,
#   so an unsupported value fails at APPLY, not at PLAN.
#   Proving which is true is a PoC objective. var.managed_ruleset_version makes
#   the fallback to "2.1" a one-line change.
#
# A Front Door WAF policy is a GLOBAL resource. It has no location argument, but
# it must sit in the same SUBSCRIPTION as the Front Door profile.
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

resource "azurerm_cdn_frontdoor_firewall_policy" "this" {
  name                = var.name
  resource_group_name = var.resource_group_name
  sku_name            = "Premium_AzureFrontDoor" # managed rules require Premium
  enabled             = true
  mode                = var.mode
  tags                = var.tags

  # Default Rule Set
  managed_rule {
    type    = "Microsoft_DefaultRuleSet"
    version = var.managed_ruleset_version
    action  = "Block"

    dynamic "exclusion" {
      for_each = var.exclusions
      content {
        match_variable = exclusion.value.match_variable
        selector       = exclusion.value.selector
        operator       = exclusion.value.selector_match_operator
      }
    }

    dynamic "override" {
      for_each = var.rule_group_overrides
      content {
        rule_group_name = override.value.rule_group_name
        dynamic "rule" {
          for_each = override.value.rules
          content {
            rule_id = rule.value.id
            enabled = rule.value.enabled
            # DRS 2.0+ : Log or AnomalyScoring only
            action = rule.value.action
          }
        }
      }
    }
  }

  # Bot Manager — Premium only
  managed_rule {
    type    = "Microsoft_BotManagerRuleSet"
    version = var.bot_manager_version
    action  = var.bot_action
  }

  # ------------------------------------- bands 1-39: central mandatory rules
  dynamic "custom_rule" {
    for_each = var.central_rules
    content {
      name     = custom_rule.value.name
      priority = custom_rule.value.priority
      type     = "MatchRule"
      action   = custom_rule.value.action
      enabled  = true

      dynamic "match_condition" {
        for_each = custom_rule.value.match_conditions
        content {
          match_variable     = match_condition.value.match_variable
          selector           = lookup(match_condition.value, "selector", null)
          operator           = match_condition.value.operator
          negation_condition = lookup(match_condition.value, "negate", false)
          match_values       = match_condition.value.match_values
        }
      }
    }
  }

  # ----------------------------------------------- band 40-69: rate limits
  # Front Door counts per socket IP PER EDGE SERVER. Thresholds below roughly
  # 200/min leak before blocking, which is why the baseline uses 5-minute
  # windows with proportionally larger thresholds.
  dynamic "custom_rule" {
    for_each = var.rate_limit_rules
    content {
      name                           = custom_rule.value.name
      priority                       = custom_rule.value.priority
      type                           = "RateLimitRule"
      action                         = custom_rule.value.action
      enabled                        = true
      rate_limit_duration_in_minutes = custom_rule.value.duration_minutes
      rate_limit_threshold           = custom_rule.value.threshold

      dynamic "match_condition" {
        for_each = custom_rule.value.match_conditions
        content {
          match_variable     = match_condition.value.match_variable
          selector           = lookup(match_condition.value, "selector", null)
          operator           = match_condition.value.operator
          negation_condition = lookup(match_condition.value, "negate", false)
          match_values       = match_condition.value.match_values
        }
      }
    }
  }

  # ----------------------------------- band 70-100: application team rules
  dynamic "custom_rule" {
    for_each = var.application_rules
    content {
      name     = custom_rule.value.name
      priority = custom_rule.value.priority
      type     = "MatchRule"
      action   = custom_rule.value.action
      enabled  = true

      dynamic "match_condition" {
        for_each = custom_rule.value.match_conditions
        content {
          match_variable     = match_condition.value.match_variable
          selector           = lookup(match_condition.value, "selector", null)
          operator           = match_condition.value.operator
          negation_condition = lookup(match_condition.value, "negate", false)
          match_values       = match_condition.value.match_values
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition = alltrue([
        for r in var.application_rules : r.priority >= 70 && r.priority <= 100
      ])
      error_message = "Application rules must use priority 70-100. Bands 1-69 are reserved for central rules."
    }
  }
}

###############################################################################
# Security policy — binds the WAF policy to the endpoint or custom domain.
# NOTE: patterns_to_match only accepts ["/*"] on this resource. Per-path WAF
# scoping is an Application Gateway capability, not a Front Door one.
###############################################################################
resource "azurerm_cdn_frontdoor_security_policy" "this" {
  count = length(var.associated_domain_ids) == 0 ? 0 : 1

  name                     = "${var.name}-secpol"
  cdn_frontdoor_profile_id = var.cdn_frontdoor_profile_id

  security_policies {
    firewall {
      cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.this.id

      association {
        dynamic "domain" {
          for_each = var.associated_domain_ids
          content {
            cdn_frontdoor_domain_id = domain.value
          }
        }
        patterns_to_match = ["/*"]
      }
    }
  }
}
