terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.81.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "0.14.0"
    }
  }
  required_version = ">= 1.16.5"
}

# No subscription_id. The subscription comes from the credentials the pipeline
# (or your az login) is using, so the same code cannot accidentally target the
# wrong one.
provider "azurerm" {
  storage_use_azuread = true
  features {}
}
