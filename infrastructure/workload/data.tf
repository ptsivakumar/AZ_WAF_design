###############################################################################
# data.tf — things that already exist and are consumed, not created.
#
# Currently minimal, because nothing has been confirmed to pre-exist in sbx.
# As the sandbox gains shared resources, move them from main.tf into here.
#
# NOTE: azurerm_client_config was commented out upstream (commit "refactor:
# Comment out azurerm_client_config data source in data.tf"). It is left out
# here deliberately — nothing below needs it. Add it back only when something
# genuinely needs the tenant or object id.
###############################################################################

# Subscription the provider is authenticated against. Used for tagging and
# outputs only — never for hardcoding an id anywhere.
data "azurerm_subscription" "current" {}

# ---------------------------------------------------------------------------
# OPTIONAL: an existing Log Analytics workspace.
#
# Set log_analytics_workspace_name and log_analytics_resource_group_name in
# workload.tfvars to send WAF diagnostics to a workspace that already exists.
# Leave both null and the workload creates its own.
# ---------------------------------------------------------------------------
data "azurerm_log_analytics_workspace" "existing" {
  count               = var.log_analytics_workspace_name == null ? 0 : 1
  name                = var.log_analytics_workspace_name
  resource_group_name = var.log_analytics_resource_group_name
}

# ---------------------------------------------------------------------------
# OPTIONAL: an existing virtual network to place the Application Gateway in.
#
# Application Gateway needs a dedicated subnet. If sbx already has a network,
# set existing_vnet_name / existing_vnet_resource_group_name / appgw_subnet_name
# and the workload consumes them instead of creating its own.
# ---------------------------------------------------------------------------
data "azurerm_subnet" "appgw" {
  count                = var.existing_vnet_name == null ? 0 : 1
  name                 = var.appgw_subnet_name
  virtual_network_name = var.existing_vnet_name
  resource_group_name  = var.existing_vnet_resource_group_name
}
