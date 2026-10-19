###############################################################################
# exceptions.tf — the exception gate.
#
# Everything here is evaluated at PLAN time. No Azure resource is read or
# created, nothing needs enable_appgw or enable_frontdoor to be true, and the
# whole file costs nothing to run. A pull request that breaks one of these
# rules goes red about fifteen seconds in.
#
# WHAT IS CHECKED WHERE, AND WHY IT IS SPLIT
#
#   variables.tf      shape, scope, format. Things that are true or false
#                     about a single exclusion in isolation — is it scoped to
#                     a rule group, does it name an owner, is the date a date.
#
#   exceptions.tf     things that depend on WHEN THE PLAN RUNS. Terraform
#                     cannot call plantimestamp() inside a variable
#                     validation, so expiry has to be checked here.
#
#   the module        things that need the policy itself.
#
# The split is not cosmetic. An expiry check in a variable validation would
# silently never fire.
#
# WHY terraform_data
#
# A null_resource would need the null provider, which versions.tf does not
# declare and which is Renovate-managed. terraform_data is built into
# Terraform, needs no provider, and carries lifecycle preconditions. It
# creates one trivial entry in state and nothing in Azure.
###############################################################################

locals {
  # One list, both platforms, so a reviewer reads a single register rather
  # than two. Platform is carried so an error message can say which one.
  all_exceptions = concat(
    [for e in var.appgw_exclusions : {
      platform      = "Application Gateway"
      scope         = e.rule_group_name
      field         = "${e.match_variable}:${e.selector}"
      narrowed_to   = length(e.excluded_rules) > 0 ? join(",", e.excluded_rules) : "whole rule group"
      justification = e.justification
      requested_by  = e.requested_by
      risk_owner    = e.risk_owner
      ticket        = e.ticket
      expires       = e.expires
    }],
    [for e in var.afd_exclusions : {
      platform      = "Front Door"
      scope         = e.rule_group_name
      field         = "${e.match_variable}:${e.selector}"
      narrowed_to   = join(",", e.rule_ids)
      justification = e.justification
      requested_by  = e.requested_by
      risk_owner    = e.risk_owner
      ticket        = e.ticket
      expires       = e.expires
    }],
  )

  # An exclusion is live until the end of its expiry day, so compare against
  # 23:59:59Z rather than midnight. timecmp returns -1 when the first argument
  # is earlier, so "still valid" is < 0.
  expired_exceptions = [
    for e in local.all_exceptions :
    "${e.ticket} (${e.platform}, ${e.field}, expired ${e.expires}, risk owner ${e.risk_owner})"
    if timecmp(plantimestamp(), "${e.expires}T23:59:59Z") >= 0
  ]

  # The longest expiry this plan is allowed to grant.
  max_expiry = timeadd(plantimestamp(), "${var.max_exception_days * 24}h")

  overlong_exceptions = [
    for e in local.all_exceptions :
    "${e.ticket} (expires ${e.expires})"
    if timecmp("${e.expires}T23:59:59Z", local.max_expiry) > 0
  ]

  # Central rules are defined in central-rules.tf, not in tfvars, so an
  # application team cannot collide with them by construction. This catches
  # security colliding with itself — two central rules at the same priority
  # is an apply-time failure that is cheaper to find here.
  central_priority_clashes = concat(
    length(distinct(local.central_appgw_priorities)) == length(local.central_appgw_priorities) ? [] : ["Application Gateway"],
    length(distinct(local.central_afd_priorities)) == length(local.central_afd_priorities) ? [] : ["Front Door"],
  )
}

resource "terraform_data" "exception_gate" {
  # Stored so `terraform show` reads as an exception register rather than an
  # empty resource. Nothing downstream depends on it.
  input = {
    exceptions_in_force = length(local.all_exceptions)
    reviewed_at         = plantimestamp()
    register            = local.all_exceptions
  }

  lifecycle {
    # ---------------------------------------------------------------- expiry
    precondition {
      condition = length(local.expired_exceptions) == 0
      error_message = join("\n", concat(
        ["EXPIRED WAF EXCLUSION — this plan is blocked.", "",
        "These exclusions have passed their expiry date:"],
        [for x in local.expired_exceptions : "  - ${x}"],
        ["",
          "An exclusion is a temporary exception, not a permanent setting. Either",
          "the false positive has been fixed in the application, in which case",
          "delete the exclusion, or it has not, in which case the owner renews it",
          "with a fresh ticket and a new expiry date.",
          "",
          "Renewing by bumping the date without re-reading the justification is",
          "how a WAF ends up switched off one field at a time.",
        ],
      ))
    }

    # ------------------------------------------------------- grant too long
    precondition {
      condition = length(local.overlong_exceptions) == 0
      error_message = join("\n", concat(
        ["WAF EXCLUSION GRANTED FOR TOO LONG — this plan is blocked.", "",
        "Maximum at creation is ${var.max_exception_days} days. These exceed it:"],
        [for x in local.overlong_exceptions : "  - ${x}"],
        ["",
          "A year is not an exception, it is a decision nobody made. Shorten the",
          "expiry, or raise max_exception_days in the tfvars and explain why in",
          "the pull request so the decision is visible.",
        ],
      ))
    }

    # ------------------------------------------- security colliding with itself
    precondition {
      condition     = length(local.central_priority_clashes) == 0
      error_message = "Duplicate priorities among the central rules in central-rules.tf (${join(", ", local.central_priority_clashes)}). Azure requires custom rule priorities to be unique within a policy."
    }
  }
}

###############################################################################
# NOT A REGISTER — A VIEW.
#
# Nobody maintains this. It is generated from the exclusions that exist in
# code, at the moment you ask, so it cannot drift from reality: it IS reality,
# read out in a different shape. Delete an exclusion and it leaves here the
# same second.
#
# That distinction matters. A register is a document somebody tends, and every
# organisation's is wrong within a quarter. This is a projection.
#
# What it deliberately does NOT hold is the DECISION — the risk acceptance,
# the approval, the business justification. Those live in the organisation's
# own exception process, where audit looks and where approvers already work.
# The ticket number is the join between the two. We reference, we do not
# duplicate.
###############################################################################

output "waf_exceptions_in_force" {
  description = "Every WAF exclusion active on this workload, with risk owner, justification, ticket and expiry. Generated from code, not maintained."
  value       = local.all_exceptions
}

output "waf_central_rules_enforced" {
  description = "What the platform enforces on this workload regardless of what the application team asked for. Sourced from central-rules.tf, which is CODEOWNERS-protected."
  value = {
    appgw = [for r in concat(
      [for x in local.central_appgw_rules : { name = x.name, priority = x.priority, action = x.action }],
      [for x in local.central_appgw_rate_limits : { name = x.name, priority = x.priority, action = "Block" }],
    ) : r]
    afd = [for r in concat(
      [for x in local.central_afd_rules : { name = x.name, priority = x.priority, action = x.action }],
      [for x in local.central_afd_rate_limits : { name = x.name, priority = x.priority, action = x.action }],
    ) : r]
  }
}

output "waf_application_rules" {
  description = "What the application team added in band 70-100. The contrast with waf_central_rules_enforced is the operating model in two outputs."
  value = {
    appgw = [for r in var.appgw_application_rules : { name = r.name, priority = r.priority, action = r.action }]
    afd   = [for r in var.afd_application_rules : { name = r.name, priority = r.priority, action = r.action }]
  }
}
