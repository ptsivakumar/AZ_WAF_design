###############################################################################
# central-rules.tf — OWNED BY SECURITY. NOT BY THE APPLICATION TEAM.
#
# WHY THIS IS A .tf FILE AND NOT A .tfvars ENTRY
#
# The application team owns environments/<env>/workload.tfvars. If the central
# rules lived there, any team could edit, reorder or quietly delete one and the
# plan would still succeed — the control would rest on nobody noticing.
#
# Putting them in a Terraform file covered by CODEOWNERS means a pull request
# that touches them cannot merge without security approval. The control is
# enforced by the repository, not by trust:
#
#   .github/CODEOWNERS
#     infrastructure/workload/central-rules.tf   @<security-team>
#
# WHAT "CENTRALLY MANAGED" CAN AND CANNOT MEAN ON AZURE
#
# A WAF policy cannot be shared across subscriptions or regions — an
# Application Gateway policy must sit in the same subscription AND region as
# the gateway. So there is no single policy covering the estate, and anyone who
# promises one has not read the constraint.
#
# What is central is THIS FILE. The same definitions are rendered into every
# policy the platform creates. Central definitions, federated enforcement.
# That distinction is the whole operating model.
#
# PRIORITY BANDS — lower number is evaluated first, 1-100, unique per policy
#
#     1-9    emergency virtual patch   security   (a CVE, applied the same day)
#    10-39   mandatory central rules   security
#    40-69   rate limits               security
#   70-100   application-specific      app team, security approved
#
# An application rule outside 70-100 fails the plan. See exceptions.tf.
###############################################################################

locals {

  # ===========================================================================
  # THE BASELINE — the minimum every workload must meet.
  #
  # These sit in this file, not in variables.tf, for the same reason the rules
  # do: an application team's tfvars cannot reach them. Weakening the baseline
  # requires a pull request against a CODEOWNERS-protected file.
  #
  # guardrails.tf turns each of these into a plan-time check.
  # ===========================================================================

  # Bump when anything in this file changes. Stamped onto every resource as a
  # tag, so one Resource Graph query answers "who is running old central
  # rules" without needing Azure Policy aliases:
  #
  #   resources
  #   | where type =~ 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies'
  #   | extend v = tostring(tags['waf-baseline-version'])
  #   | where v != '1.0.0' or isempty(v)
  #
  baseline_version = "1.0.0"

  # Managed rule set versions. A tfvars cannot go below these outside sbx.
  # Application Gateway documents 2.1 and 2.2; Front Door only reaches 2.1 on
  # azurerm 4.81. The asymmetry is a provider constraint, not a choice.
  required_appgw_ruleset = "2.2"
  required_afd_ruleset   = "2.1"
  required_bot_manager   = "1.1"

  # Environments where Detection mode is an acceptable steady state. Elsewhere
  # Detection is an onboarding phase and needs a dated waiver.
  detection_ok_environments = ["sbx", "dev"]

  # Environments where origin lockdown is mandatory. Sandbox is excluded so
  # the bypass test can still be run unlocked to produce the "before" half of
  # the evidence.
  lockdown_optional_environments = ["sbx"]

  # Longest an exception may be granted, by environment. Production risk is
  # not the same risk as development risk, so the ceiling is not the same
  # number.
  max_exception_days_by_env = {
    sbx  = 90
    dev  = 90
    stag = 60
    prd  = 30
  }

  # Minimum gateway instances. RATE LIMIT THRESHOLDS ARE PER INSTANCE, so a
  # single-instance gateway admits the threshold once per instance and every
  # published limit becomes a number nobody can rely on.
  min_capacity_by_env = {
    sbx  = 1
    dev  = 1
    stag = 2
    prd  = 2
  }

  # ===========================================================================
  # APPLICATION GATEWAY — bands 10-39
  #
  # match_conditions within one rule are ANDed. Separate rules are ORed.
  # variable_name: RemoteAddr | RequestMethod | QueryString | PostArgs |
  #                RequestUri | RequestHeaders | RequestBody | RequestCookies
  # operator:      Any | IPMatch | GeoMatch | Equal | Contains | LessThan |
  #                GreaterThan | LessThanOrEqual | GreaterThanOrEqual |
  #                BeginsWith | EndsWith | Regex
  # ===========================================================================
  central_appgw_rules = [
    {
      # Source-control and configuration files that should never be served.
      # Scanners probe for these within minutes of an application appearing on
      # the internet. Blocking them is uncontroversial and costs nothing.
      name     = "blockSensitivePaths"
      priority = 10
      action   = "Block"
      match_conditions = [
        {
          variable_name = "RequestUri"
          operator      = "Contains"
          match_values = [
            "/.git",
            "/.env",
            "/.aws",
            "/web.config",
            "/wp-admin",
            "/phpmyadmin",
          ]
        },
      ]
    },
    {
      # TRACE and TRACK enable cross-site tracing. No legitimate application
      # needs them. OPTIONS is left alone because CORS preflight requires it.
      name     = "blockDangerousHttpMethods"
      priority = 11
      action   = "Block"
      match_conditions = [
        {
          variable_name = "RequestMethod"
          operator      = "Equal"
          match_values  = ["TRACE", "TRACK"]
        },
      ]
    },
  ]

  # ----------------------------------------- Application Gateway, band 40-69
  # THRESHOLDS ARE PER GATEWAY INSTANCE, not per gateway. A gateway scaled to
  # four instances admits roughly four times this number before any rule fires.
  # Size the threshold against min_capacity, not against the traffic you see.
  central_appgw_rate_limits = [
    {
      name      = "rateLimitPerClientAddr"
      priority  = 40
      duration  = "FiveMins" # OneMin | FiveMins
      threshold = 2000
      group_by  = "ClientAddr"
      match_conditions = [
        {
          variable_name = "RemoteAddr"
          operator      = "IPMatch"
          match_values  = ["0.0.0.0/0"]
        },
      ]
    },
  ]

  # ===========================================================================
  # FRONT DOOR — the same intent, different field names.
  #
  # Front Door uses match_variable (not variable_name) and its own value list:
  # Cookies | PostArgs | QueryString | RemoteAddr | RequestBody |
  # RequestHeader | RequestMethod | RequestUri | SocketAddr
  #
  # The lists are deliberately kept side by side rather than generated from one
  # source. Making them look identical would hide the fact that they are not.
  # ===========================================================================
  central_afd_rules = [
    {
      name     = "blockSensitivePaths"
      priority = 10
      action   = "Block"
      match_conditions = [
        {
          match_variable = "RequestUri"
          operator       = "Contains"
          match_values = [
            "/.git",
            "/.env",
            "/.aws",
            "/web.config",
            "/wp-admin",
            "/phpmyadmin",
          ]
        },
      ]
    },
    {
      name     = "blockDangerousHttpMethods"
      priority = 11
      action   = "Block"
      match_conditions = [
        {
          match_variable = "RequestMethod"
          operator       = "Equal"
          match_values   = ["TRACE", "TRACK"]
        },
      ]
    },
  ]

  # ------------------------------------------------- Front Door, band 40-69
  # Front Door counts per socket IP PER EDGE SERVER. A threshold below roughly
  # 200 per minute leaks before it blocks, which is why the baseline uses a
  # five-minute window with a proportionally larger threshold.
  central_afd_rate_limits = [
    {
      name             = "rateLimitPerSocketAddr"
      priority         = 40
      action           = "Block"
      duration_minutes = 5
      threshold        = 2000
      match_conditions = [
        {
          match_variable = "RemoteAddr"
          operator       = "IPMatch"
          match_values   = ["0.0.0.0/0"]
        },
      ]
    },
  ]

  # ===========================================================================
  # Derived — used by the exception gate and the plan-time outputs.
  # ===========================================================================
  central_appgw_priorities = concat(
    [for r in local.central_appgw_rules : r.priority],
    [for r in local.central_appgw_rate_limits : r.priority],
  )
  central_afd_priorities = concat(
    [for r in local.central_afd_rules : r.priority],
    [for r in local.central_afd_rate_limits : r.priority],
  )
}
