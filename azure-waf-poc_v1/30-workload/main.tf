###############################################################################
# 30-workload — test application, Application Gateway (Pattern B),
#               Front Door Premium (Pattern A), and origin lockdown.
#
# This layer is what the guardrails in 10-platform are evaluated against, and
# what tests/bypass-test.sh attacks. Runbook steps 1.4, 3.x and 4.x.
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
  subscription_id = var.subscription_id
}

locals {
  tags = merge(var.tags, {
    "security-waf-profile" = var.waf_profile
    "application-owner"    = var.application_owner
  })
}

# Create a resource group, or reuse one that already exists.
# In the ccoe-waf-sbx sandbox the group ccoe-waf-poc-rg already exists, so
# create_resource_group = false and Terraform binds to it instead of trying
# to create it. Terraform does NOT adopt an unmanaged resource on apply —
# without this it would fail with "A resource with this ID already exists".
resource "azurerm_resource_group" "wl" {
  count    = var.create_resource_group ? 1 : 0
  name     = var.resource_group_name
  location = var.location
  tags     = local.tags
}

data "azurerm_resource_group" "wl" {
  count = var.create_resource_group ? 0 : 1
  name  = var.resource_group_name
}

locals {
  rg_name     = var.create_resource_group ? azurerm_resource_group.wl[0].name : data.azurerm_resource_group.wl[0].name
  rg_location = var.create_resource_group ? azurerm_resource_group.wl[0].location : data.azurerm_resource_group.wl[0].location
}

###############################################################################
# Test application — deliberately trivial. Its only job is to be an origin.
###############################################################################
resource "azurerm_service_plan" "app" {
  name                = "${var.prefix}-plan"
  resource_group_name = local.rg_name
  location            = local.rg_location
  os_type             = "Linux"
  sku_name            = var.app_service_sku
  tags                = local.tags
}

resource "azurerm_linux_web_app" "app" {
  name                = "${var.prefix}-app-${random_string.sfx.result}"
  resource_group_name = local.rg_name
  location            = azurerm_service_plan.app.location
  service_plan_id     = azurerm_service_plan.app.id
  https_only          = true
  tags                = local.tags

  site_config {
    always_on = var.app_service_sku != "F1"

    # ---------------------------------------------------- ORIGIN LOCKDOWN
    # var.lockdown_enabled is FALSE for the first apply, on purpose.
    # Runbook step 4.1 runs the bypass test against the UNLOCKED app to
    # establish the baseline, then flips this to true and re-runs it.
    # Without the before-and-after pair the test proves nothing.
    ip_restriction_default_action = var.lockdown_enabled ? "Deny" : "Allow"

    dynamic "ip_restriction" {
      for_each = var.lockdown_enabled ? [1] : []
      content {
        name        = "Allow-FrontDoor-only"
        action      = "Allow"
        priority    = 100
        service_tag = "AzureFrontDoor.Backend"

        # The service tag ALONE is not a lockdown - it admits any tenant's
        # Front Door. The header check against OUR profile GUID is what makes
        # it a control. resource_guid is the X-Azure-FDID value.
        headers {
          x_azure_fdid      = [azurerm_cdn_frontdoor_profile.fd.resource_guid]
          x_fd_health_probe = ["1"]
        }
      }
    }

    application_stack {
      node_version = "20-lts"
    }
  }

  app_settings = {
    WEBSITE_RUN_FROM_PACKAGE = "0"
  }
}

resource "random_string" "sfx" {
  length  = 5
  special = false
  upper   = false
}

###############################################################################
# Pattern B — Application Gateway WAF_v2
###############################################################################
module "waf_appgw" {
  source = "../20-modules/waf-policy-appgw"

  name                = "${var.prefix}appgwwaf"
  resource_group_name = local.rg_name
  # MUST equal the gateway's region - same region AND subscription.
  location                   = local.rg_location
  mode                       = var.waf_mode
  managed_ruleset_version    = var.appgw_ruleset_version
  log_analytics_workspace_id = var.log_analytics_workspace_id
  tags                       = local.tags

  # Band 10-39 — a central mandatory rule
  central_rules = [{
    name     = "BlockKnownBadUserAgent"
    priority = 10
    action   = "Block"
    match_conditions = [{
      variable_name = "RequestHeaders"
      selector      = "User-Agent"
      operator      = "Contains"
      match_values  = ["sqlmap", "nikto", "nmap"]
    }]
  }]

  # Band 40-69 — central rate-limit template.
  # NOTE: the threshold is per gateway INSTANCE. A 2-instance gateway
  # permits up to 2x this figure. Runbook step 4.6 measures the real number.
  rate_limit_rules = [{
    name      = "StandardVolumetric"
    priority  = 40
    duration  = "FiveMins"
    threshold = 1000
    group_by  = "ClientAddr"
    match_conditions = [{
      variable_name = "RemoteAddr"
      operator      = "IPMatch"
      match_values  = ["0.0.0.0/0"]
    }]
  }]

  # Band 70-100 — application team rule. Priority below 70 fails the
  # module precondition, which is the point of step 3.4.
  application_rules = var.application_rules

  # Populated by step 4.4 after a false positive is identified in Detection.
  exclusions = var.exclusions
}

resource "azurerm_public_ip" "agw" {
  name                = "${var.prefix}-agw-pip"
  resource_group_name = local.rg_name
  location            = local.rg_location
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_virtual_network" "spoke" {
  name                = "${var.prefix}-spoke-vnet"
  resource_group_name = local.rg_name
  location            = local.rg_location
  address_space       = ["10.80.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "agw" {
  name                 = "snet-appgw"
  resource_group_name  = local.rg_name
  virtual_network_name = azurerm_virtual_network.spoke.name
  address_prefixes     = ["10.80.1.0/24"]
}

resource "azurerm_application_gateway" "agw" {
  name                = "${var.prefix}-agw"
  resource_group_name = local.rg_name
  location            = local.rg_location
  tags                = local.tags

  sku {
    name = "WAF_v2"
    tier = "WAF_v2"
  }

  autoscale_configuration {
    min_capacity = 1
    max_capacity = 2
  }

  # Gateway-wide policy. Per-listener and per-path association use
  # firewall_policy_id on http_listener and path_rule respectively.
  firewall_policy_id                = module.waf_appgw.id
  force_firewall_policy_association = true

  gateway_ip_configuration {
    name      = "gwip"
    subnet_id = azurerm_subnet.agw.id
  }

  frontend_port {
    name = "port80"
    port = 80
  }

  frontend_ip_configuration {
    name                 = "feip"
    public_ip_address_id = azurerm_public_ip.agw.id
  }

  backend_address_pool {
    name  = "appservice-pool"
    fqdns = [azurerm_linux_web_app.app.default_hostname]
  }

  backend_http_settings {
    name                                = "https-settings"
    cookie_based_affinity               = "Disabled"
    port                                = 443
    protocol                            = "Https"
    request_timeout                     = 30
    pick_host_name_from_backend_address = true
  }

  http_listener {
    name                           = "listener-http"
    frontend_ip_configuration_name = "feip"
    frontend_port_name             = "port80"
    protocol                       = "Http"
  }

  request_routing_rule {
    name                       = "rule-1"
    priority                   = 100
    rule_type                  = "Basic"
    http_listener_name         = "listener-http"
    backend_address_pool_name  = "appservice-pool"
    backend_http_settings_name = "https-settings"
  }
}

###############################################################################
# Pattern A — Front Door Premium
###############################################################################
resource "azurerm_cdn_frontdoor_profile" "fd" {
  name                = "${var.prefix}-fd"
  resource_group_name = local.rg_name
  sku_name            = "Premium_AzureFrontDoor"
  tags                = local.tags
}

resource "azurerm_cdn_frontdoor_endpoint" "fd" {
  name                     = "${var.prefix}-ep"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.fd.id
  tags                     = local.tags
}

resource "azurerm_cdn_frontdoor_origin_group" "fd" {
  name                     = "${var.prefix}-og"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.fd.id

  # Required block even though every field inside it is optional.
  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }

  health_probe {
    path                = "/"
    protocol            = "Https"
    request_type        = "HEAD"
    interval_in_seconds = 100
  }
}

resource "azurerm_cdn_frontdoor_origin" "fd" {
  name                          = "${var.prefix}-origin"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.fd.id
  enabled                       = true

  host_name          = azurerm_linux_web_app.app.default_hostname
  origin_host_header = azurerm_linux_web_app.app.default_hostname
  http_port          = 80
  https_port         = 443
  priority           = 1
  weight             = 500

  certificate_name_check_enabled = true # Required, not optional
}

resource "azurerm_cdn_frontdoor_route" "fd" {
  name                          = "${var.prefix}-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.fd.id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.fd.id
  cdn_frontdoor_origin_ids      = [azurerm_cdn_frontdoor_origin.fd.id]

  supported_protocols    = ["Http", "Https"]
  patterns_to_match      = ["/*"]
  forwarding_protocol    = "HttpsOnly"
  https_redirect_enabled = true
  link_to_default_domain = true
}

module "waf_afd" {
  source = "../20-modules/waf-policy-afd"

  name                     = "${var.prefix}fdwaf"
  resource_group_name      = local.rg_name
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.fd.id
  associated_domain_ids    = [azurerm_cdn_frontdoor_endpoint.fd.id]
  mode                     = var.waf_mode
  managed_ruleset_version  = var.afd_ruleset_version # see step 4.2
  bot_action               = var.bot_action
  tags                     = local.tags

  rate_limit_rules = [{
    name             = "StandardVolumetric"
    priority         = 40
    action           = "Block"
    duration_minutes = 5 # baseline standardises on the 5-minute window
    threshold        = 1000
    match_conditions = [{
      match_variable = "RequestUri"
      operator       = "Any"
      match_values   = []
    }]
  }]
}

###############################################################################
# Diagnostics on the gateway itself (the policy-driven path is control 8;
# this proves the manual path so the two can be compared).
###############################################################################
resource "azurerm_monitor_diagnostic_setting" "agw" {
  count                      = var.log_analytics_workspace_id == null ? 0 : 1
  name                       = "agw-diagnostics"
  target_resource_id         = azurerm_application_gateway.agw.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log { category_group = "allLogs" }
  metric { category = "AllMetrics" }
}

resource "azurerm_monitor_diagnostic_setting" "fd" {
  count                      = var.log_analytics_workspace_id == null ? 0 : 1
  name                       = "fd-diagnostics"
  target_resource_id         = azurerm_cdn_frontdoor_profile.fd.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log { category_group = "allLogs" }
  metric { category = "AllMetrics" }
}
