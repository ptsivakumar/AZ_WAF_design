###############################################################################
# 00-bootstrap — Terraform state backend. Run ONCE with local state, then
# migrate the other layers onto it. Runbook step 1.1.
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
  subscription_id = var.platform_sub_id
}

resource "azurerm_resource_group" "tfstate" {
  name     = "${var.prefix}-tfstate-rg"
  location = var.location
}

resource "azurerm_storage_account" "tfstate" {
  name                            = "${var.prefix}tfstate${random_string.suffix.result}"
  resource_group_name             = azurerm_resource_group.tfstate.name
  location                        = azurerm_resource_group.tfstate.location
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

variable "platform_sub_id" {
  type = string
}

output "backend_config" {
  value = <<-EOT
    Add to each layer:

    terraform {
      backend "azurerm" {
        resource_group_name  = "${azurerm_resource_group.tfstate.name}"
        storage_account_name = "${azurerm_storage_account.tfstate.name}"
        container_name       = "tfstate"
        key                  = "<layer>.tfstate"
      }
    }
  EOT
}
