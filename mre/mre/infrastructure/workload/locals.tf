###############################################################################
# locals.tf — naming and shared values.
#
# Naming follows the convention visible in the existing backend resources:
#   rg-westeurope-tfbackend   ->  rg-<location>-<purpose>
# so this workload produces rg-westeurope-waf and so on. Override through
# workload.tfvars if the team standard differs — better to correct the pattern
# than to have two conventions in one repo.
#
# NO random provider. versions.tf declares only azurerm and time, and it is
# Renovate-managed, so this file must not create a reason to edit it. Globally
# unique names derive deterministically from the subscription id instead, which
# also makes them stable across re-applies.
###############################################################################

locals {
  # Matches the names already in sbx: ccoe-waf-poc-rg, ccoe-waf-poc-vnet,
  # ccoe-waf-sbx-appgw. Keeping one convention per subscription matters more
  # than matching the platform team's rg-<location>-<purpose> backend naming,
  # which belongs to a different layer.
  base = var.name_prefix

  # Deterministic 6-char suffix for globally unique names. Same subscription,
  # same workload, same name every time — no provider needed.
  uniq = substr(sha1("${data.azurerm_subscription.current.subscription_id}-${var.workload}"), 0, 6)

  names = {
    resource_group   = var.resource_group_name
    vnet             = "${local.base}-vnet"
    appgw_subnet     = var.appgw_subnet_name
    public_ip        = "${local.base}-appgw-pip"
    app_service_plan = "${local.base}-asp"
    web_app          = "${local.base}-app-${local.uniq}"      # globally unique
    appgw            = "${local.base}-appgw-tf"               # -tf so it cannot clash with the hand-built one
    waf_appgw        = "${local.base}-appgw-wafpolicy"
    waf_afd          = "${replace(local.base, "-", "")}afdwaf" # AFD policy names: letters and digits only
    frontdoor        = "${local.base}-afd"
    frontdoor_ep     = "${local.base}-fde-${local.uniq}"      # globally unique
    log_analytics    = "${local.base}-law"
  }

  tags = merge(
    var.tags,
    {
      workload               = var.workload
      "security-waf-profile" = var.waf_profile
      "application-owner"    = var.application_owner
      managed-by             = "terraform"
    }
  )

  # Resolved once so main.tf never branches on "existing or created".
  log_analytics_workspace_id = (
    var.log_analytics_workspace_name != null
    ? data.azurerm_log_analytics_workspace.existing[0].id
    : (var.create_log_analytics ? azurerm_log_analytics_workspace.this[0].id : null)
  )

  appgw_subnet_id = (
    var.existing_vnet_name != null
    ? data.azurerm_subnet.appgw[0].id
    : azurerm_subnet.appgw[0].id
  )
}
