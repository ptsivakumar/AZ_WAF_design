# ---------------------------------------------------------------------------
# sandbox.tfvars — the ONLY file you have to edit.
#
# One value is missing: subscription_id. Everything else is already set for
# [sandbox-subscription-name] / [resource-grp-name].
#
#   az account set --subscription "[sandbox-subscription-name]"
#   az account show --query id -o tsv          <- paste the GUID below
#
# Then pass this file to every layer:
#
#   cd 10-platform-sub && terraform init && terraform apply -var-file=../sandbox.tfvars
#   cd ../30-workload  && terraform init && terraform apply -var-file=../sandbox.tfvars
#
# Only these six keys live here. They are declared in every layer, so no
# layer will complain about an undeclared variable. Layer-specific settings
# (waf_mode, lockdown_enabled, enable_policy, afd_ruleset_version ...) are
# passed with -var on the command line, because they change during the PoC
# and the point is that each change is a deliberate, logged action.
# ---------------------------------------------------------------------------

subscription_id = "PASTE-THE-GUID-HERE"

resource_group_name   = "[resource-grp-name]"
create_resource_group = false

prefix   = "wafpoc"
location = "westeurope"

tags = {
  purpose    = "waf-poc"
  owner      = "ccoe"
  disposable = "true"
}
