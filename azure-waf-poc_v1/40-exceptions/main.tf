###############################################################################
# 40-exceptions — Azure Policy exemptions for the application-team exception
#                 process. Validation steps V1 to V6 in the exception design.
#
# AN EXEMPTION IS NOT AN EXCLUSION.
#   Exclusion  = WAF tuning. Lives in the WAF policy module. Resource stays
#                Compliant. No expiry. See 20-modules/.
#   Exemption  = governance waiver. The workload cannot meet a CONTROL.
#                Resource becomes Exempt. Expiry mandatory. This file.
#
# KEY BEHAVIOURS (verified against Microsoft Learn, Oct 2026):
#   - exemption_category is "Waiver" or "Mitigated" — nothing else.
#   - policy_definition_reference_ids scopes the exemption to SPECIFIC
#     controls inside the initiative. Omitting it exempts the resource from
#     ALL THIRTEEN. That is the commonest and most damaging mistake.
#   - At expires_on the object is NOT deleted. It is kept for the record but
#     stops being honoured, so the resource silently reverts to normal
#     evaluation. Nothing warns you. Reporting is the control.
#   - Creating an exemption needs TWO permissions:
#       Microsoft.Authorization/policyExemptions/write  on the resource, AND
#       exempt/Action                                   on the assignment.
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
  # Load every approved exception record. One YAML file per exception, so the
  # register is reviewable in a pull request rather than in a spreadsheet.
  record_files = fileset("${path.module}/records", "*.yaml")
  records = {
    for f in local.record_files :
    trimsuffix(f, ".yaml") => yamldecode(file("${path.module}/records/${f}"))
  }

  # Only records that are approved AND not yet past expiry are applied.
  # An expired record stays in the repository as history but stops being
  # deployed - mirroring Azure's own behaviour.
  active = {
    for k, r in local.records : k => r
    if r.status == "approved" && timecmp(timestamp(), "${r.expiryDate}T00:00:00Z") < 0
  }
}

resource "azurerm_resource_policy_exemption" "this" {
  for_each = local.active

  name                 = each.value.exceptionId
  display_name         = "${each.value.exceptionId} — ${each.value.application}"
  resource_id          = each.value.resourceId
  policy_assignment_id = var.policy_assignment_id

  # Mitigated = the control's intent is met another way, with evidence.
  # Waiver    = the risk is temporarily accepted, remediation plan required.
  exemption_category = each.value.category

  # Scope to the named controls ONLY. Never leave this empty.
  policy_definition_reference_ids = each.value.exemptFromControls

  expires_on = "${each.value.expiryDate}T00:00:00Z"

  description = each.value.businessReason

  metadata = jsonencode({
    exceptionId          = each.value.exceptionId
    application          = each.value.application
    owner                = each.value.owner
    securityApprover     = each.value.securityApprover
    approvedOn           = each.value.approvedOn
    renewalCount         = each.value.renewalCount
    compensatingControls = each.value.compensatingControls
    remediationPlan      = lookup(each.value, "remediationPlan", null)
  })

  lifecycle {
    precondition {
      condition     = length(each.value.exemptFromControls) > 0
      error_message = "${each.key}: exemptFromControls must name at least one control. An empty list exempts the resource from the ENTIRE initiative."
    }
    precondition {
      condition     = each.value.category == "Mitigated" ? length(each.value.compensatingControls) > 0 : true
      error_message = "${each.key}: a Mitigated exemption must evidence at least one compensating control. If there are none, the category is Waiver."
    }
    precondition {
      condition     = each.value.category == "Waiver" ? can(each.value.remediationPlan) : true
      error_message = "${each.key}: a Waiver must carry a dated remediation plan."
    }
    precondition {
      condition     = each.value.renewalCount < 2 || can(each.value.remediationPlan)
      error_message = "${each.key}: a second renewal requires a dated remediation plan."
    }
  }
}
