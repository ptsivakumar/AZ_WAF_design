###############################################################################
# 00-bootstrap — Terraform state backend. Run ONCE with local state, then
# migrate the other layers onto it. Runbook step 1.1.
#
# OPTIONAL FOR DAY 1. A remote backend matters when the Azure DevOps pipeline
# runs the apply, or when more than one person touches the environment. If it
# is only you on a laptop this week, skip this layer, let Terraform keep state
# in local files, and come back to it before wiring up the pipeline.
#
# If you DO run it with create_resource_group = false, the state storage lands
# in the same resource group as everything else. Deleting that group then
# destroys the state along with the resources it describes. Acceptable in a
# sandbox; never do it in production.
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

resource "azurerm_resource_group" "tfstate" {
  count    = var.create_resource_group ? 1 : 0
  name     = var.resource_group_name
  location = var.location
}

data "azurerm_resource_group" "tfstate" {
  count = var.create_resource_group ? 0 : 1
  name  = var.resource_group_name
}

locals {
  rg_name     = var.create_resource_group ? azurerm_resource_group.tfstate[0].name : data.azurerm_resource_group.tfstate[0].name
  rg_location = var.create_resource_group ? azurerm_resource_group.tfstate[0].location : data.azurerm_resource_group.tfstate[0].location
}

resource "azurerm_storage_account" "tfstate" {
  name                            = "${var.prefix}tfstate${random_string.suffix.result}"
  resource_group_name             = local.rg_name
  location                        = local.rg_location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  blob_properties {
    versioning_enabled = true
  }
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "azurerm_storage_container" "tfstate" {
  name                  = "tfstate"
  storage_account_id    = azurerm_storage_account.tfstate.id
  container_access_type = "private"
}

variable "prefix" {
  type    = string
  default = "wafpoc"
}

variable "location" {
  type    = string
  default = "westeurope"
}

variable "subscription_id" {
  type        = string
  description = "Subscription GUID. For ccoe-waf-sbx: az account show --subscription ccoe-waf-sbx --query id -o tsv"
}

variable "resource_group_name" {
  type    = string
  default = "ccoe-waf-poc-rg"
}

variable "create_resource_group" {
  type        = bool
  default     = false
  description = "ccoe-waf-poc-rg already exists, so leave this false."
}

output "backend_config" {
  value = <<-EOT
    Add to each layer:

    terraform {
      backend "azurerm" {
        resource_group_name  = "${local.rg_name}"
        storage_account_name = "${azurerm_storage_account.tfstate.name}"
        container_name       = "tfstate"
        key                  = "<layer>.tfstate"
      }
    }
  EOT
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Declared so the shared ../sandbox.tfvars applies cleanly to every layer."
}
