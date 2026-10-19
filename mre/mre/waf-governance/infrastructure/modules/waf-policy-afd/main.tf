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

# No provider block here — the root module's versions.tf owns provider
# configuration. A module declares only what it REQUIRES.
terraform {
  required_version = ">= 1.16.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.81"
    }
  }
}

###############################################################################
# Merging rule-group overrides with scoped exclusions.
#
# Front Door allows ONE override block per rule group. An explicit rule
# override and an exclusion attached to a rule in the same group therefore
# have to be emitted together, or the second silently replaces the first.
#
# Every override this module emits contains at least one rule block, because
# azurerm documents that an override with no rules disables the entire group.
# The precondition below enforces that for overrides supplied by the caller.
###############################################################################
locals {
  # Every rule group that needs an override block, from either source.
  afd_groups = distinct(concat(
    [for o in var.rule_group_overrides : o.rule_group_name],
    [for e in var.exclusions : e.rule_group_name],
  ))

  # Rules the caller explicitly overrode, flattened with their group.
  afd_explicit_rules = flatten([
    for o in var.rule_group_overrides : [
      for r in o.rules : {
        group   = o.rule_group_name
        id      = r.id
        enabled = r.enabled
        action  = r.action
      }
    ]
  ])

  # Settings lookup: "GROUP|RULEID" -> the caller's intent.
  afd_rule_settings = {
    for r in local.afd_explicit_rules : "${r.group}|${r.id}" => r
  }

  # Rules that need a block only because an exclusion hangs off them. These
  # keep their default behaviour — enabled, anomaly scoring — and carry the
  # exclusion. DRS 2.0 and above accept only Log or AnomalyScoring here.
  afd_rules_by_group = {
    for g in local.afd_groups : g => distinct(concat(
      [for r in local.afd_explicit_rules : r.id if r.group == g],
      flatten([for e in var.exclusions : e.rule_ids if e.rule_group_name == g]),
    ))
  }

  afd_empty_overrides = [
    for o in var.rule_group_overrides : o.rule_group_name if length(o.rules) == 0
  ]
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

    # NO POLICY-WIDE EXCLUSION BLOCK HERE, DELIBERATELY.
    #
    # An exclusion at this level applies to every rule in the rule set. It is
    # the single easiest way to switch most of a WAF off while a dashboard
    # still reports the policy as enabled. Exclusions are emitted below,
    # attached to the individual rules that actually produced the false
    # positive.

    dynamic "override" {
      for_each = local.afd_groups
      content {
        rule_group_name = override.value

        dynamic "rule" {
          for_each = local.afd_rules_by_group[override.value]
          content {
            rule_id = rule.value

            # A rule that exists only to carry an exclusion keeps its default
            # behaviour. One the caller overrode keeps the caller's intent.
            enabled = try(local.afd_rule_settings["${override.value}|${rule.value}"].enabled, true)
            action  = try(local.afd_rule_settings["${override.value}|${rule.value}"].action, "AnomalyScoring")

            dynamic "exclusion" {
              for_each = [
                for e in var.exclusions : e
                if e.rule_group_name == override.value && contains(e.rule_ids, rule.value)
              ]
              content {
                match_variable = exclusion.value.match_variable
                operator       = exclusion.value.operator
                selector       = exclusion.value.selector
              }
            }
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
    precondition {
      condition     = length(local.afd_empty_overrides) == 0
      error_message = "rule_group_override with no rules for: ${join(", ", local.afd_empty_overrides)}. On Front Door that DISABLES EVERY RULE IN THE GROUP rather than doing nothing. If that is genuinely what you want, say so explicitly in a ticket and raise it with security — it is not something a plan should let through quietly."
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

  lifecycle {
    precondition {
      condition     = var.cdn_frontdoor_profile_id != null
      error_message = "cdn_frontdoor_profile_id must be set when associated_domain_ids is non-empty."
    }
  }

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
