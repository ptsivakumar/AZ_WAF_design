###############################################################################
# main.tf — Azure WAF workload
#
#   Pattern A : Front Door Premium + WAF policy   (global ingress)
#   Pattern B : Application Gateway WAF_v2 + WAF policy  (regional ingress)
#   Plus a trivial App Service whose only job is to be an origin, and the
#   origin lockdown that makes the WAF unbypassable.
#
# NO terraform{} OR provider{} BLOCK IN THIS FILE.
# versions.tf owns both: azurerm 4.81.0, storage_use_azuread = true, and no
# subscription_id — the subscription comes from the pipeline's credentials.
# Declaring a second provider block here would conflict.
#
# EVERYTHING IS TOGGLEABLE. Front Door Premium and Application Gateway bill by
# the hour whether used or not, so each pattern has its own switch. Start with
# one, not both.
###############################################################################

# ---------------------------------------------------------------- foundation
resource "azurerm_resource_group" "this" {
  count    = var.create_resource_group ? 1 : 0
  name     = local.names.resource_group
  location = var.location
  tags     = local.tags
}

data "azurerm_resource_group" "this" {
  count = var.create_resource_group ? 0 : 1
  name  = local.names.resource_group
}

locals {
  rg_name     = var.create_resource_group ? azurerm_resource_group.this[0].name : data.azurerm_resource_group.this[0].name
  rg_location = var.create_resource_group ? azurerm_resource_group.this[0].location : data.azurerm_resource_group.this[0].location
}

resource "azurerm_log_analytics_workspace" "this" {
  count = var.create_log_analytics && var.log_analytics_workspace_name == null ? 1 : 0

  name                = local.names.log_analytics
  resource_group_name = local.rg_name
  location            = local.rg_location
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = local.tags
}

# ------------------------------------------------------------------ network
# Only created when no existing vnet is supplied. Application Gateway requires
# a subnet of its own — it cannot share.
resource "azurerm_virtual_network" "this" {
  count = var.existing_vnet_name == null && var.enable_appgw ? 1 : 0

  name                = local.names.vnet
  resource_group_name = local.rg_name
  location            = local.rg_location
  address_space       = [var.vnet_address_space]
  tags                = local.tags
}

resource "azurerm_subnet" "appgw" {
  count = var.existing_vnet_name == null && var.enable_appgw ? 1 : 0

  name                 = local.names.appgw_subnet
  resource_group_name  = local.rg_name
  virtual_network_name = azurerm_virtual_network.this[0].name
  address_prefixes     = [var.appgw_subnet_prefix]
}

# ------------------------------------------------------- origin application
# Deliberately trivial. Its only job is to be something to put a WAF in front
# of, and something to try to reach directly in the bypass test.
resource "azurerm_service_plan" "this" {
  name                = local.names.app_service_plan
  resource_group_name = local.rg_name
  location            = local.rg_location
  os_type             = "Linux"
  sku_name            = var.app_service_sku
  tags                = local.tags
}

resource "azurerm_linux_web_app" "this" {
  name                = local.names.web_app
  resource_group_name = local.rg_name
  location            = local.rg_location
  service_plan_id     = azurerm_service_plan.this.id
  https_only          = true
  tags                = local.tags

  site_config {
    always_on = var.app_service_sku != "F1"

    application_stack {
      node_version = "20-lts"
    }

    # ----------------------------------------------------- ORIGIN LOCKDOWN
    # The control that makes the WAF worth having. With this off, anyone can
    # reach the origin directly and the WAF is decoration.
    #
    # Deny-by-default, with a single Allow for traffic arriving from our own
    # Front Door profile — matched on BOTH the service tag and the
    # X-Azure-FDID header. The service tag alone is not enough: it covers
    # every customer's Front Door, not just ours.
    ip_restriction_default_action = var.lockdown_enabled ? "Deny" : "Allow"

    dynamic "ip_restriction" {
      for_each = var.lockdown_enabled && var.enable_frontdoor ? [1] : []
      content {
        name        = "allow-our-frontdoor"
        action      = "Allow"
        priority    = 100
        service_tag = "AzureFrontDoor.Backend"
        headers {
          x_azure_fdid      = [azurerm_cdn_frontdoor_profile.this[0].resource_guid]
          x_fd_health_probe = ["1"]
        }
      }
    }

    # Application Gateway reaches the origin from its public IP, so lockdown
    # for Pattern B is an IP allow rather than a service tag.
    dynamic "ip_restriction" {
      for_each = var.lockdown_enabled && var.enable_appgw ? [1] : []
      content {
        name       = "allow-our-appgw"
        action     = "Allow"
        priority   = 110
        ip_address = "${azurerm_public_ip.appgw[0].ip_address}/32"
      }
    }
  }
}

resource "azurerm_monitor_diagnostic_setting" "web_app" {
  count = local.log_analytics_workspace_id == null ? 0 : 1

  name                       = "diag-web-app"
  target_resource_id         = azurerm_linux_web_app.this.id
  log_analytics_workspace_id = local.log_analytics_workspace_id

  enabled_log { category = "AppServiceHTTPLogs" }
  metric { category = "AllMetrics" }
}

###############################################################################
# PATTERN B — Application Gateway WAF_v2
#
# The WAF policy MUST be in the same subscription AND the same region as the
# gateway. That constraint is why the operating model is federated rather than
# central, and it is the strongest argument in the design proposal.
###############################################################################

module "waf_appgw" {
  count  = var.enable_appgw ? 1 : 0
  source = "../modules/waf-policy-appgw"

  name                = local.names.waf_appgw
  resource_group_name = local.rg_name
  location            = local.rg_location # same region as the gateway — enforced by construction
  tags                = local.tags

  mode                    = var.waf_mode
  managed_ruleset_version = var.appgw_ruleset_version
  bot_manager_version     = var.bot_manager_version

  log_analytics_workspace_id = local.log_analytics_workspace_id

  central_rules     = var.appgw_central_rules
  rate_limit_rules  = var.appgw_rate_limit_rules
  application_rules = var.appgw_application_rules
  exclusions        = var.appgw_exclusions
}

resource "azurerm_public_ip" "appgw" {
  count = var.enable_appgw ? 1 : 0

  name                = local.names.public_ip
  resource_group_name = local.rg_name
  location            = local.rg_location
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_application_gateway" "this" {
  count = var.enable_appgw ? 1 : 0

  name                = local.names.appgw
  resource_group_name = local.rg_name
  location            = local.rg_location
  tags                = local.tags

  firewall_policy_id = module.waf_appgw[0].id

  sku {
    name = "WAF_v2"
    tier = "WAF_v2"
  }

  autoscale_configuration {
    min_capacity = var.appgw_min_capacity
    max_capacity = var.appgw_max_capacity
  }

  gateway_ip_configuration {
    name      = "gateway-ip"
    subnet_id = local.appgw_subnet_id
  }

  frontend_port {
    name = "port-80"
    port = 80
  }

  frontend_ip_configuration {
    name                 = "frontend-ip"
    public_ip_address_id = azurerm_public_ip.appgw[0].id
  }

  backend_address_pool {
    name  = "origin-pool"
    fqdns = [azurerm_linux_web_app.this.default_hostname]
  }

  backend_http_settings {
    name                                = "origin-https"
    cookie_based_affinity               = "Disabled"
    port                                = 443
    protocol                            = "Https"
    request_timeout                     = 30
    pick_host_name_from_backend_address = true
  }

  http_listener {
    name                           = "listener-http"
    frontend_ip_configuration_name = "frontend-ip"
    frontend_port_name             = "port-80"
    protocol                       = "Http"
  }

  request_routing_rule {
    name                       = "rule-default"
    priority                   = 100
    rule_type                  = "Basic"
    http_listener_name         = "listener-http"
    backend_address_pool_name  = "origin-pool"
    backend_http_settings_name = "origin-https"
  }
}

resource "azurerm_monitor_diagnostic_setting" "appgw" {
  count = var.enable_appgw && local.log_analytics_workspace_id != null ? 1 : 0

  name                       = "diag-appgw"
  target_resource_id         = azurerm_application_gateway.this[0].id
  log_analytics_workspace_id = local.log_analytics_workspace_id

  enabled_log { category_group = "allLogs" }
  metric { category = "AllMetrics" }
}

###############################################################################
# PATTERN A — Front Door Premium
#
# Premium is required for managed WAF rules and Private Link origins. The WAF
# is included in the Premium base fee, so Premium is the price of admission
# rather than a WAF surcharge.
#
# COST: a Front Door profile is billed for every hour OR PARTIAL HOUR it is
# deployed. Set enable_frontdoor = false when not actively testing it.
###############################################################################

module "waf_afd" {
  count  = var.enable_frontdoor ? 1 : 0
  source = "../modules/waf-policy-afd"

  name                = local.names.waf_afd
  resource_group_name = local.rg_name
  tags                = local.tags

  mode = var.waf_mode
  # DEFAULTS TO 2.1 ON PURPOSE. azurerm 4.81 documents Microsoft_DefaultRuleSet
  # 1.1 / 2.0 / 2.1 for Front Door, and 2.1 / 2.2 for Application Gateway.
  # The asymmetry is real at the provider level. See README.
  managed_ruleset_version = var.afd_ruleset_version
  bot_manager_version     = var.bot_manager_version

  log_analytics_workspace_id = local.log_analytics_workspace_id

  # Front Door rule blocks use DIFFERENT field names from Application Gateway
  # (match_variable vs variable_name; duration_minutes vs duration/group_by),
  # so each platform gets its own lists. Passing one set to both looks tidy
  # and fails at apply.
  bot_action        = var.afd_bot_action
  central_rules     = var.afd_central_rules
  rate_limit_rules  = var.afd_rate_limit_rules
  application_rules = var.afd_application_rules
  exclusions        = var.afd_exclusions
}

resource "azurerm_cdn_frontdoor_profile" "this" {
  count = var.enable_frontdoor ? 1 : 0

  name                = local.names.frontdoor
  resource_group_name = local.rg_name
  sku_name            = "Premium_AzureFrontDoor"
  tags                = local.tags
}

resource "azurerm_cdn_frontdoor_endpoint" "this" {
  count = var.enable_frontdoor ? 1 : 0

  name                     = local.names.frontdoor_ep
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this[0].id
  tags                     = local.tags
}

resource "azurerm_cdn_frontdoor_origin_group" "this" {
  count = var.enable_frontdoor ? 1 : 0

  name                     = "origin-group"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this[0].id

  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }

  health_probe {
    interval_in_seconds = 100
    path                = "/"
    protocol            = "Https"
    request_type        = "HEAD"
  }
}

resource "azurerm_cdn_frontdoor_origin" "this" {
  count = var.enable_frontdoor ? 1 : 0

  name                           = "origin-app"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.this[0].id
  enabled                        = true
  host_name                      = azurerm_linux_web_app.this.default_hostname
  origin_host_header             = azurerm_linux_web_app.this.default_hostname
  http_port                      = 80
  https_port                     = 443
  priority                       = 1
  weight                         = 1
  certificate_name_check_enabled = true
}

resource "azurerm_cdn_frontdoor_route" "this" {
  count = var.enable_frontdoor ? 1 : 0

  name                          = "route-default"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.this[0].id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.this[0].id
  cdn_frontdoor_origin_ids      = [azurerm_cdn_frontdoor_origin.this[0].id]

  supported_protocols    = ["Http", "Https"]
  patterns_to_match      = ["/*"]
  forwarding_protocol    = "HttpsOnly"
  https_redirect_enabled = true
  link_to_default_domain = true
}

# The WAF policy only takes effect once it is bound to a domain through a
# security policy. A policy that exists but is not associated protects nothing
# — an easy and expensive thing to miss.
resource "azurerm_cdn_frontdoor_security_policy" "this" {
  count = var.enable_frontdoor ? 1 : 0

  name                     = "secpol-waf"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this[0].id

  security_policies {
    firewall {
      cdn_frontdoor_firewall_policy_id = module.waf_afd[0].id

      association {
        domain {
          cdn_frontdoor_domain_id = azurerm_cdn_frontdoor_endpoint.this[0].id
        }
        patterns_to_match = ["/*"]
      }
    }
  }
}

resource "azurerm_monitor_diagnostic_setting" "frontdoor" {
  count = var.enable_frontdoor && local.log_analytics_workspace_id != null ? 1 : 0

  name                       = "diag-frontdoor"
  target_resource_id         = azurerm_cdn_frontdoor_profile.this[0].id
  log_analytics_workspace_id = local.log_analytics_workspace_id

  enabled_log { category_group = "allLogs" }
  metric { category = "AllMetrics" }
}
