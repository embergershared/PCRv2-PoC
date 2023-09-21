#--------------------------------------------------------------
#   Terraform providers
#--------------------------------------------------------------
terraform {
  required_version = ">=1.0"

  required_providers {
    azurerm = {
      # https://registry.terraform.io/providers/hashicorp/azurerm/latest
      source  = "hashicorp/azurerm"
      version = ">=3.0"
    }
    azuread = {
      # https://registry.terraform.io/providers/hashicorp/azuread/latest
      source  = "hashicorp/azuread"
      version = ">= 2.0"
    }
  }
}
provider "azurerm" {
  tenant_id       = var.tenant_id
  subscription_id = var.subscription_id
  client_id       = var.client_id
  client_secret   = var.client_secret

  skip_provider_registration = true
  storage_use_azuread        = true

  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}
provider "azurerm" {
  alias = "external"

  tenant_id       = var.tenant_id
  subscription_id = var.external_subscription_id
  client_id       = var.client_id
  client_secret   = var.client_secret

  skip_provider_registration = true
  storage_use_azuread        = true

  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}
provider "azuread" {
  # To App registration creation = use of azsp module,
  # The following API Permissions must be added to the Terraform Service Principal:
  #   Application.ReadWrite.All + Grant admin consent
  #   When authenticated with a user principal, azuread_application requires one of the following directory roles: Application Administrator or Global Administrator
  #
  # More info here: https://registry.terraform.io/providers/hashicorp/azuread/latest/docs/resources/application
}
