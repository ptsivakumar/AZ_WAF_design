# =============================================================================
# sbx — Azure WAF workload
#
# No subscription_id and no tenant_id here. versions.tf configures the provider
# without one, so the subscription comes from the pipeline's credentials, and
# the backend ids live in workload.tfbackend.
#
# Run order — one change per run, so every result has a before and an after:
#   1. as below                                    baseline, Pattern B, unlocked
#   2. lockdown_enabled = true                     the bypass test proof
#   3. waf_mode = "Prevention"                     after tuning
#   4. enable_frontdoor = true                     Pattern A  (BILLABLE PER HOUR)
# =============================================================================

workload    = "waf"
location    = "westeurope"
name_prefix = "waf-sbx" # matches the existing waf-sbx-appgw

# ----------------------------------------------------------------- toggles
#
# PHASE 1 (now): both false. Terraform creates ONLY the App Service origin and
# Log Analytics. Your hand-built waf-sbx-appgw is untouched, nothing is
# destroyed, and the first apply takes about two minutes instead of twenty-five.
# The point of run 1 is to learn the pipeline, not to build the gateway.
#
# PHASE 2: enable_appgw = true. Terraform builds its OWN gateway, named
# waf-sbx-appgw-tf so it cannot clash with yours. Two WAF_v2 gateways
# cost roughly EUR 10-12 a day extra — fine for days, not for a month.
#
# PHASE 3: once Terraform's gateway works, delete the hand-built one.
enable_appgw     = false
enable_frontdoor = false # Front Door Premium bills per hour or partial hour.

# CONFIRMED IN THE PORTAL — these already exist, so Terraform consumes them
# rather than creating them. Terraform never adopts resources it did not make.
resource_group_name               = "waf-poc-rg"
create_resource_group             = false
existing_vnet_name                = "waf-poc-vnet" # 10.0.0.0/16
existing_vnet_resource_group_name = "waf-poc-rg"
appgw_subnet_name                 = "appgw-subnet"      # 10.0.1.0/24, no NSG

create_log_analytics = true

# Step 2 flips this to true. Leave false for the first apply — the unlocked
# bypass test is the baseline half of the evidence.
lockdown_enabled = false

# ------------------------------------------------------------- WAF baseline
waf_mode              = "Detection"
appgw_ruleset_version = "2.2" # documented for Application Gateway on azurerm 4.81
afd_ruleset_version   = "2.1" # 2.2 is NOT documented for Front Door on 4.81
bot_manager_version   = "1.1"

# --------------------------------------------------------------- sizing
app_service_sku    = "B1"
appgw_min_capacity = 1
appgw_max_capacity = 2

# Network values are not needed — the existing vnet and subnet are consumed
# above. vnet_address_space / appgw_subnet_prefix are only used when Terraform
# creates its own network, which it will not here.
#
# If a Log Analytics workspace already exists, add these and set
# create_log_analytics = false:
# log_analytics_workspace_name      = "..."
# log_analytics_resource_group_name = "..."

# -------------------------------------------------------------------- tags
application_owner = "platform-team"
waf_profile       = "web-standard"

tags = {
  environment = "sbx"
  purpose     = "waf-poc"
  disposable  = "true"
}

# -------------------------------------------------- rules and exclusions
# Empty on the first apply, deliberately. Exclusions are populated at the
# tuning step from a real false positive seen in Detection mode, not guessed
# up front.
# Application Gateway and Front Door use different field names for the same
# concepts, so each has its own lists. See workload/variables.tf.
appgw_central_rules     = []
appgw_rate_limit_rules  = []
appgw_application_rules = []
appgw_exclusions        = []

afd_central_rules     = []
afd_rate_limit_rules  = []
afd_application_rules = []
afd_exclusions        = []
afd_bot_action        = "Log" # Block for the critical profile
