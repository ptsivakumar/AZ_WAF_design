###############################################################################
# import.tf — TEMPORARY. DELETE AFTER ONE SUCCESSFUL APPLY.
#
# WHY THIS EXISTS
#
# Four resources exist in Azure but are absent from sbx.workload.tfstate, so
# Terraform refused to adopt them:
#
#   Error: a resource with the ID "..." already exists - to be managed via
#   Terraform this resource needs to be imported into the State.
#
# Terraform never adopts a resource it did not create. That is deliberate and
# correct: silently taking ownership of something it found is how a tool ends
# up destroying a resource somebody else depends on.
#
# WHY CONFIG-DRIVEN IMPORT RATHER THAN `terraform import`
#
# The CLI command needs a workstation with Terraform and Azure credentials.
# An import BLOCK is part of the configuration, so the existing pipeline
# performs the import during its normal plan and apply. Nothing new is needed,
# and the operation is reviewable in a pull request rather than being
# something one person ran on a laptop.
#
# HOW TO READ THE NEXT PLAN
#
# Each of these should appear as:
#
#   azurerm_service_plan.this: Preparing import... [id=...]
#   # azurerm_service_plan.this will be imported
#
# and the summary should read:
#
#   Plan: 2 to add, 0 to change, 0 to destroy, 4 to import.
#
# IF IT SAYS ANYTHING WILL BE DESTROYED, STOP. That would mean an ID is wrong
# and Terraform intends to replace a live resource rather than adopt it.
#
# AFTER IT SUCCEEDS
#
# Delete this file. The imports are recorded in state and re-running them is
# noise. Leaving it also leaves a trap: if someone later deletes a resource
# deliberately, these blocks make the next plan fail with a confusing error.
###############################################################################

locals {
  # Read at plan time, so the subscription id is not written into the repo.
  import_rg_id = "/subscriptions/${data.azurerm_subscription.current.subscription_id}/resourceGroups/${var.resource_group_name}"

  # VERIFY THIS AGAINST THE PORTAL BEFORE MERGING.
  # Derived the same way locals.tf derives it, so it should match what the
  # first apply created — but a one-character difference fails the import.
  import_web_app_name = local.names.web_app
}

# ------------------------------------------------------------- App Service plan
import {
  to = azurerm_service_plan.this
  id = "${local.import_rg_id}/providers/Microsoft.Web/serverFarms/${local.names.app_service_plan}"
}

# ------------------------------------------------------------------ Web app
import {
  to = azurerm_linux_web_app.this
  id = "${local.import_rg_id}/providers/Microsoft.Web/sites/${local.import_web_app_name}"
}

# ------------------------------------------------- Log Analytics workspace
import {
  to = azurerm_log_analytics_workspace.this[0]
  id = "${local.import_rg_id}/providers/Microsoft.OperationalInsights/workspaces/${local.names.log_analytics}"
}

# --------------------------------------------------------- diagnostic setting
# A diagnostic setting is an extension resource. Its import ID is the TARGET
# resource id, a pipe, then the setting name — not a resource id of its own.
import {
  to = azurerm_monitor_diagnostic_setting.web_app[0]
  id = "${local.import_rg_id}/providers/Microsoft.Web/sites/${local.import_web_app_name}|diag-web-app"
}
