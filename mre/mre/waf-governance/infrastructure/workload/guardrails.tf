###############################################################################
# guardrails.tf — the baseline, enforced.
#
# central-rules.tf states what the minimum is. This file refuses to plan when
# a tfvars falls below it.
#
# WHAT IS *NOT* HERE, AND WHY
#
# Three things a guardrail would obviously check are absent on purpose:
#
#   gateway SKU is WAF_v2         hardcoded in main.tf
#   WAF policy is associated      hardcoded — firewall_policy_id is the module
#   request_body_check is true    hardcoded in the module
#
# None of them is a variable, so nobody can weaken them, so a check would be
# theatre — a control that looks real and enforces nothing already guaranteed.
# They DO matter for gateways built outside this repository, which is an Azure
# Policy problem, not a pipeline one. See the module map, section 2.
#
# A check belongs here only when there is a way to get it wrong.
#
# Everything below runs at plan time, needs no Azure resource, and works with
# enable_appgw = false.
###############################################################################

locals {
  env             = var.environment
  lockdown_needed = !contains(local.lockdown_optional_environments, local.env)
  detection_ok    = contains(local.detection_ok_environments, local.env)

  # Detection outside sbx/dev is allowed only while a waiver is live. The
  # waiver is itself an exception: ticketed, owned, and dated.
  mode_waiver_live = (
    var.waf_mode_waiver != null
    ? timecmp(plantimestamp(), "${var.waf_mode_waiver.expires}T23:59:59Z") < 0
    : false
  )

  max_exception_days_allowed = local.max_exception_days_by_env[local.env]
  min_capacity_required      = local.min_capacity_by_env[local.env]

  # Unset means "whatever this environment requires", so the common case needs
  # no decision and still cannot be wrong.
  appgw_min_capacity = coalesce(var.appgw_min_capacity, local.min_capacity_required)
}

resource "terraform_data" "guardrails" {
  input = {
    environment      = local.env
    baseline_version = local.baseline_version
    checked_at       = plantimestamp()
  }

  lifecycle {
    # ------------------------------------------------------- origin lockdown
    #
    # The control the whole thing rests on. A WAF whose origin is still
    # reachable directly is decoration — evidenced, not argued: before
    # lockdown a SQL injection sent straight to the origin returned 200.
    precondition {
      condition     = !local.lockdown_needed || var.lockdown_enabled
      error_message = <<-EOT
        ORIGIN LOCKDOWN IS OFF in environment "${local.env}".

        Set lockdown_enabled = true. Without it the application is reachable
        directly, the WAF sits in front of one path and the application answers
        on another, and an attacker does not choose the monitored route.

        Only ${join(", ", local.lockdown_optional_environments)} may run unlocked, so the
        bypass test can produce its "before" evidence.

        Lockdown must cover the SCM site as well as the main site —
        <app>.scm.azurewebsites.net is a separate hostname reaching the same
        application. The module sets both.
      EOT
    }

    # ------------------------------------------------------------- WAF mode
    #
    # Detection is the right setting while onboarding and the wrong one
    # forever. The quietest way to disable a WAF is to set Detection
    # "temporarily" and never set it back, so outside sbx and dev it needs a
    # waiver that expires.
    precondition {
      condition = (
        var.waf_mode == "Prevention"
        || local.detection_ok
        || local.mode_waiver_live
      )
      error_message = <<-EOT
        WAF IS IN DETECTION MODE in environment "${local.env}".

        Detection observes and logs. It blocks nothing. It is correct during
        onboarding and wrong as a steady state.

        Either set waf_mode = "Prevention", or declare an onboarding waiver
        with an expiry date:

          waf_mode_waiver = {
            justification = "Onboarding. Tuning false positives from Detection logs."
            risk_owner    = "application.owner@example.com"
            ticket        = "SEC-1234"
            expires       = "YYYY-MM-DD"
          }

        The waiver expiring is what stops "temporarily" becoming permanent.
        ${var.waf_mode_waiver != null ? "The current waiver expired on ${var.waf_mode_waiver.expires}." : ""}
      EOT
    }

    # -------------------------------------------------- managed rule set floor
    #
    # Lowering the rule set version is the same move as switching to
    # Detection, one layer down: it looks like configuration and it removes
    # protection. The required versions live in central-rules.tf, under
    # CODEOWNERS.
    precondition {
      condition     = local.env == "sbx" || var.appgw_ruleset_version == local.required_appgw_ruleset
      error_message = "Application Gateway managed rule set must be ${local.required_appgw_ruleset} in ${local.env} (tfvars says ${var.appgw_ruleset_version}). The baseline is set in central-rules.tf. Only sbx may differ, for testing a version change before it is adopted."
    }
    precondition {
      condition     = local.env == "sbx" || var.afd_ruleset_version == local.required_afd_ruleset
      error_message = "Front Door managed rule set must be ${local.required_afd_ruleset} in ${local.env} (tfvars says ${var.afd_ruleset_version}). Note this is lower than Application Gateway's ${local.required_appgw_ruleset} — azurerm 4.81 does not document 2.2 for Front Door. The asymmetry is a provider constraint, not an oversight."
    }
    precondition {
      condition     = local.env == "sbx" || var.bot_manager_version == local.required_bot_manager
      error_message = "Bot Manager rule set must be ${local.required_bot_manager} in ${local.env} (tfvars says ${var.bot_manager_version})."
    }

    # --------------------------------------------------------- gateway sizing
    #
    # Not a performance check. RATE LIMIT THRESHOLDS ARE COUNTED PER INSTANCE.
    # A gateway scaled to one instance admits the threshold once; scaled to
    # four it admits roughly four times the published number. A single
    # instance in a production environment makes every rate limit in
    # central-rules.tf a figure nobody can rely on.
    precondition {
      condition = !var.enable_appgw || local.appgw_min_capacity >= local.min_capacity_required
      # NOTE: no ${var.appgw_min_capacity} here. Terraform evaluates an
      # error_message template even when its condition PASSES, and
      # interpolating null fails the plan. The variable is nullable, so the
      # effective local is what gets reported.
      error_message = "appgw_min_capacity resolves to ${local.appgw_min_capacity} but must be at least ${local.min_capacity_required} in ${local.env}. Rate limit thresholds are counted per gateway INSTANCE, so capacity below this makes the published limits meaningless — and it is also a single point of failure. Leave the variable unset to get the environment default."
    }

    # max below min fails at apply with an error that does not say why.
    precondition {
      condition     = !var.enable_appgw || var.appgw_max_capacity >= local.appgw_min_capacity
      error_message = "appgw_max_capacity (${var.appgw_max_capacity}) is below the effective minimum capacity (${local.appgw_min_capacity}) for ${local.env}."
    }

    # ------------------------------------------------- exception grant ceiling
    precondition {
      condition     = var.max_exception_days <= local.max_exception_days_allowed
      error_message = "max_exception_days is ${var.max_exception_days}, above the ${local.max_exception_days_allowed}-day ceiling for ${local.env}. Production risk is not development risk, so the ceiling is not the same number. Raising it means changing central-rules.tf, which needs security approval."
    }

    # ----------------------------------------------------------- the waiver
    precondition {
      condition = (
        var.waf_mode_waiver == null
        || can(regex("^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$", var.waf_mode_waiver.expires))
      )
      error_message = "waf_mode_waiver.expires must be a date as YYYY-MM-DD."
    }
    precondition {
      condition = (
        var.waf_mode_waiver == null
        || can(regex("^[A-Z][A-Z0-9]*-[0-9]+$", var.waf_mode_waiver.ticket))
      )
      error_message = "waf_mode_waiver.ticket must reference a change or exception record, for example SEC-1234."
    }
  }
}

###############################################################################
# What this workload is running. Published as an output so coverage reporting
# reads it from the plan rather than anyone being asked.
###############################################################################

output "waf_baseline" {
  description = "The baseline this workload is held to, and whether it currently meets it."
  value = {
    environment       = local.env
    baseline_version  = local.baseline_version
    waf_mode          = var.waf_mode
    mode_waiver       = var.waf_mode_waiver == null ? "none" : "${var.waf_mode_waiver.ticket} until ${var.waf_mode_waiver.expires}"
    lockdown_enabled  = var.lockdown_enabled
    appgw_ruleset     = var.appgw_ruleset_version
    afd_ruleset       = var.afd_ruleset_version
    bot_manager       = var.bot_manager_version
    min_capacity      = local.appgw_min_capacity
    exception_ceiling = "${local.max_exception_days_allowed} days"
  }
}
