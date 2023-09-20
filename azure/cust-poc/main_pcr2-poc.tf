# Description   : This Terraform creates an Resource Group and resources for the Zachry PoC
#                 It deploys:
#                   - 1 Resource Group,
#                   - 1 VNet, 2 subnets
#                   - 1 LAW + 1 App Insights
#                   - 1 App Service Plan + 1 Windows Web App
#

# Folder/File   : /azure/cust-poc/main_pcr2-poc.tf
# Terraform     : 1.0.+
# Providers     : azurerm 3.+
# Plugins       : none
# Modules       : none
#
# Created on    : 2023-09-04
# Created by    : Emmanuel
# Last Modified : 2023-09-19
# Last Modif by : Emmanuel
# Modif desc.   : Move Application to another Subscription
#
# Required Resource Providers:
# - Microsoft.Network
# - Microsoft.Web
# - Microsoft.Sql
# - Microsoft.KeyVault

# IMPORTANT NOTE:
#   The Private DNS Zone azurewebsites.net will require 3 entries:
#   - Obvious:
#   webapp-win-${local.full_suffix}      CNAME   webapp-win-${local.full_suffix}.privatelink.azurewebsites.net
#   - SCM for management and deployment from VS/Pipeline:
#   webapp-win-${local.full_suffix}.scm  CNAME   webapp-win-${local.full_suffix}.privatelink.azurewebsites.net
#   - SSO redirection to access SCM:
#   waws-prod-bn1-111.sso           CNAME   webapp-win-${local.full_suffix}.privatelink.azurewebsites.net
#
#   Remote Debugger Visual Studio 2022 to App Service / Function App requires "Allow public access" (can be restricted to few IPs)


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

#--------------------------------------------------------------
#   Plan's Locals and specific resources
#--------------------------------------------------------------
data "azurerm_client_config" "current" {}
resource "time_static" "this" {}
locals {
  # Plan Tag value
  tf_plan = "/azure/cust-poc/main_pcr2-poc.tf"

  # Dates formatted
  UTC_to_TZ   = "-4h" # Careful to factor DST
  TZ_suffix   = "EST"
  now         = timestamp() # in UTC
  created_now = time_static.this.rfc3339

  # UTC based
  nowUTC               = formatdate("YYYY-MM-DD hh:mm ZZZ", local.now)                                  # 2020-06-16 14:44 UTC
  nowUTCFormatted      = "${formatdate("YYYY-MM-DD", local.now)}T${formatdate("hh:mm:ss", local.now)}Z" # "2029-01-01T01:01:01Z"
  in3yearsUTC          = timeadd(local.now, "26280h")
  in3yearsUTCFormatted = "${formatdate("YYYY-MM-DD", local.in3yearsUTC)}T${formatdate("hh:mm:ss", local.in3yearsUTC)}Z" # "2029-01-01T01:01:01Z"

  # Timezone based
  TZtime         = timeadd(local.now, local.UTC_to_TZ)
  created_TZtime = timeadd(local.created_now, local.UTC_to_TZ)
  nowTZ          = "${formatdate("YYYY-MM-DD hh:mm", local.TZtime)} ${local.TZ_suffix}"              # 2020-06-16 14:44 EST
  created_nowTZ  = "${formatdate("YYYY-MM-DD hh:mm", local.created_TZtime)} ${local.TZ_suffix}"      # 2020-06-16 14:44 EST
  nowTZFormatted = "${formatdate("YYYY-MM-DD", local.TZtime)}T${formatdate("hh:mm:ss", local.now)}Z" # "2029-01-01T01:01:01Z"
  in3yearsTZ     = timeadd(local.TZtime, "26280h")

  # Tags values
  tf_workspace = terraform.workspace == "default" ? "default" : "${terraform.workspace}"
  fixed_tags = tomap({
    "Created_with" = "Terraform v1.5.6 on windows_amd64",
    "Created_on"   = "${local.created_nowTZ}",
    "Initiated_by" = "Emmanuel",
    "Tf_Plan"      = "${local.tf_plan}",
  })
  base_tags = merge(
    local.fixed_tags,
  )
}

#--------------------------------------------------------------
#   Variables
#--------------------------------------------------------------
variable "tenant_id" {}
variable "subscription_id" {}
variable "client_id" {}
variable "client_secret" {}
variable "subsc_nickname" {}
variable "subsc_adm_short" {}
variable "main_region_code" { default = null }
variable "external_subscription_id" {}
variable "external_snet_pe_id" {}

#--------------------------------------------------------------
#   External Subscription Subnet for External PEs
#--------------------------------------------------------------
data "azurerm_virtual_network" "external_vnet" {
  provider = azurerm.external

  name                = split("/", var.external_snet_pe_id)[8]
  resource_group_name = split("/", var.external_snet_pe_id)[4]
}
data "azurerm_subnet" "external_subnet" {
  provider = azurerm.external

  name                 = split("/", var.external_snet_pe_id)[10]
  virtual_network_name = data.azurerm_virtual_network.external_vnet.name
  resource_group_name  = data.azurerm_virtual_network.external_vnet.resource_group_name
}

#--------------------------------------------------------------
#   Core Resources: Values for Naming and Resource Group
#--------------------------------------------------------------
locals {
  base_name         = "pcr2"
  add_name          = "poc"
  full_suffix       = "${var.main_region_code}-${var.subsc_nickname}-${local.base_name}-${local.add_name}"
  vnet_space        = "192.168.20.0/24"
  private_dns_zones = toset(["blob.core.windows.net", "privatelink.blob.core.windows.net", "file.core.windows.net", "privatelink.file.core.windows.net", "vault.azure.net", "vaultcore.azure.net", "database.windows.net", "privatelink.database.windows.net", "cognitiveservices.azure.com"]) # "azurewebsites.net", "privatelink.azurewebsites.net",
  # external_snet_rg_name = data.azurerm_subnet.external_subnet.resource_group_name
}
#   / Main region Resource Group
module "mainregion_poc_rg" {
  # Terraform Cloud/Enterprise use
  source  = "app.terraform.io/embergertf/resourcegroup/azurerm"
  version = "~>1.3.3"

  region_code     = var.main_region_code
  subsc_code      = var.subsc_nickname
  base_name       = local.base_name
  additional_name = local.add_name
  # iterator        = local.iterator

  additional_tags = local.base_tags
}

#--------------------------------------------------------------
#   Networking and Private DNS
#--------------------------------------------------------------
#   / VNet
resource "azurerm_virtual_network" "poc_vnet" {
  name                = lower("vnet-${local.full_suffix}")
  resource_group_name = module.mainregion_poc_rg.name
  location            = module.mainregion_poc_rg.location
  address_space       = [local.vnet_space]

  tags = local.base_tags
  lifecycle { ignore_changes = [tags["BuiltOn"]] }
}
#   / Subnets
resource "azurerm_subnet" "pe_subnet" {
  name                                      = "snet-poc-pe"
  resource_group_name                       = module.mainregion_poc_rg.name
  virtual_network_name                      = azurerm_virtual_network.poc_vnet.name
  private_endpoint_network_policies_enabled = true
  address_prefixes                          = [replace(local.vnet_space, "0/24", "0/27")]
}
#   Note: a delegated subnet is required for App Svc VNet integration.
#         It prevents Private Endpoints on this subnet (PrivateEndpointCreationNotAllowedAsSubnetIsDelegated)
resource "azurerm_subnet" "appsvc_int_subnet" {
  name                 = "snet-poc-appsvc-integration"
  resource_group_name  = module.mainregion_poc_rg.name
  virtual_network_name = azurerm_virtual_network.poc_vnet.name
  address_prefixes     = [replace(local.vnet_space, "0/24", "32/27")]

  service_endpoints = [
    "Microsoft.Storage",
    "Microsoft.CognitiveServices",
  ]

  delegation {
    name = "Microsoft.Web.serverFarms"
    service_delegation {
      name    = "Microsoft.Web/serverFarms"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action", ]
    }
  }
}
#   / Private DNS Zones iterator
resource "azurerm_private_dns_zone" "this" {
  for_each = local.private_dns_zones

  name                = each.value
  resource_group_name = module.mainregion_poc_rg.name
  tags                = module.mainregion_poc_rg.tags
}
resource "azurerm_private_dns_zone_virtual_network_link" "this" {
  depends_on = [azurerm_private_dns_zone.this]

  for_each = local.private_dns_zones

  name                  = "${each.value}-to-${replace(azurerm_virtual_network.poc_vnet.name, "-", "_")}-link"
  resource_group_name   = module.mainregion_poc_rg.name
  private_dns_zone_name = each.value
  virtual_network_id    = azurerm_virtual_network.poc_vnet.id
  registration_enabled  = false
  tags                  = module.mainregion_poc_rg.tags
}
#   / NAT Gateway
resource "azurerm_public_ip" "appsvc_int_natgw_pip" {
  name                = lower("pip-for-natgw-${local.full_suffix}")
  location            = module.mainregion_poc_rg.location
  resource_group_name = module.mainregion_poc_rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = []
}
resource "azurerm_nat_gateway" "appsvc_int_natgw" {
  name                    = lower("natgw-${local.full_suffix}")
  location                = module.mainregion_poc_rg.location
  resource_group_name     = module.mainregion_poc_rg.name
  sku_name                = "Standard"
  idle_timeout_in_minutes = 10
  zones                   = []
}
resource "azurerm_nat_gateway_public_ip_association" "appsvc_int_natgw_pip_association" {
  nat_gateway_id       = azurerm_nat_gateway.appsvc_int_natgw.id
  public_ip_address_id = azurerm_public_ip.appsvc_int_natgw_pip.id
}
resource "azurerm_subnet_nat_gateway_association" "appsvc_int_natgw_snet_association" {
  subnet_id      = azurerm_subnet.appsvc_int_subnet.id
  nat_gateway_id = azurerm_nat_gateway.appsvc_int_natgw.id
}

#--------------------------------------------------------------
#   Application Service Telemetry
#--------------------------------------------------------------
#   / Main region App Service telemetry
resource "azurerm_log_analytics_workspace" "poc_law" {
  name                       = lower("law-${local.full_suffix}")
  resource_group_name        = module.mainregion_poc_rg.name
  location                   = module.mainregion_poc_rg.location
  sku                        = "PerGB2018"
  daily_quota_gb             = "0.5"
  retention_in_days          = 30
  internet_ingestion_enabled = true
  internet_query_enabled     = true
  tags                       = local.base_tags
}
resource "azurerm_application_insights" "poc_appins" {
  name                       = lower("appins-${local.full_suffix}")
  resource_group_name        = module.mainregion_poc_rg.name
  location                   = module.mainregion_poc_rg.location
  workspace_id               = azurerm_log_analytics_workspace.poc_law.id
  application_type           = "web"
  retention_in_days          = "30"
  daily_data_cap_in_gb       = "0.5"
  internet_ingestion_enabled = true
  internet_query_enabled     = true
  tags                       = local.base_tags
}

#--------------------------------------------------------------
#   Application Service Authentication App Registration
#--------------------------------------------------------------
#   / Application Registration for Azure AD authentication in the Win Web APp
resource "azuread_application" "azsp_app" {
  display_name = lower("spn-for-webapp-win-${local.full_suffix}")

  api {
    known_client_applications      = []
    mapped_claims_enabled          = false
    requested_access_token_version = 1

    oauth2_permission_scope {
      admin_consent_description  = "Allow the registered app to access webapp-win-${local.full_suffix} on behalf of the signed-in user."
      admin_consent_display_name = "Access webapp-win-${local.full_suffix}"
      enabled                    = true
      id                         = "e9b05d73-e033-4c5f-8f48-2791f8a02c44"
      type                       = "User"
      user_consent_description   = "Allow the registered app to access webapp-win-${local.full_suffix} on your behalf."
      user_consent_display_name  = "Access webapp-win-${local.full_suffix}"
      value                      = "user_impersonation"
    }
  }
  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000"

    resource_access {
      id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
      type = "Scope"
    }
  }
  web {
    homepage_url = "https://webapp-win-${local.full_suffix}.azurewebsites.net"
    redirect_uris = [
      "http://localhost:5081/signin-oidc",
      "https://webapp-win-${local.full_suffix}.azurewebsites.net/.auth/login/aad/callback",
    ]

    implicit_grant {
      access_token_issuance_enabled = false
      id_token_issuance_enabled     = true
    }
  }
}
resource "azuread_service_principal" "azsp_sp" {
  application_id = azuread_application.azsp_app.application_id
}
resource "azuread_application_password" "azsp_app_pwd" {
  application_object_id = azuread_application.azsp_app.id
  end_date_relative     = "26280h" # 3 years
}

#--------------------------------------------------------------
#   Azure SQL Server + Database
#--------------------------------------------------------------
#   / Main region SQL Server + DB
resource "azurerm_mssql_server" "poc_sql_server" {
  name                = lower("sqlsvr-${local.full_suffix}")
  resource_group_name = module.mainregion_poc_rg.name
  location            = module.mainregion_poc_rg.location
  version             = "12.0"

  azuread_administrator {
    azuread_authentication_only = true
    login_username              = "eb@mngenvmcap446692.onmicrosoft.com"
    object_id                   = "16f07509-4609-4a32-a816-2c7178c313a3"
  }
}
resource "azurerm_mssql_database" "poc_sql_db" {
  name         = lower("sqldb-poc")
  server_id    = azurerm_mssql_server.poc_sql_server.id
  collation    = "SQL_Latin1_General_CP1_CI_AS"
  license_type = "LicenseIncluded"
  max_size_gb  = 2
  sku_name     = "S0"
}
module "sqlsvr_local_pe" {
  source     = "../../terraform-modules/pe"
  depends_on = [azurerm_private_dns_zone_virtual_network_link.this]

  resource_id         = azurerm_mssql_server.poc_sql_server.id
  resource_group_name = module.mainregion_poc_rg.name
  location            = module.mainregion_poc_rg.location

  subnet_id            = azurerm_subnet.pe_subnet.id
  subresource_names    = ["sqlServer"]
  is_manual_connection = false

  privdns_rg_name = module.mainregion_poc_rg.name
  cname_zone      = "database.windows.net"
  a_zone          = "privatelink.database.windows.net"
  ttl             = 10

  tags = local.base_tags
}
module "sqlsvr_external_pe" {
  providers = { azurerm = azurerm.external }
  source    = "../../terraform-modules/pe"

  resource_id = azurerm_mssql_server.poc_sql_server.id

  resource_group_name  = data.azurerm_subnet.external_subnet.resource_group_name
  location             = data.azurerm_virtual_network.external_vnet.location
  subnet_id            = data.azurerm_subnet.external_subnet.id
  subresource_names    = ["sqlServer"]
  is_manual_connection = false

  privdns_rg_name = data.azurerm_subnet.external_subnet.resource_group_name
  cname_zone      = "database.windows.net"
  a_zone          = "privatelink.database.windows.net"
  ttl             = 10

  tags = local.base_tags
}

#--------------------------------------------------------------
#   Storage Accounts
#--------------------------------------------------------------
#   / Drop Storage
resource "azurerm_storage_account" "drop_st" {
  name                = lower(replace("st-${local.full_suffix}-drop", "-", ""))
  resource_group_name = module.mainregion_poc_rg.name
  location            = module.mainregion_poc_rg.location

  account_kind             = "StorageV2"
  account_tier             = "Standard"
  account_replication_type = "RAGRS"

  allow_nested_items_to_be_public = false    #Disable anonymous public read access to containers and blobs
  enable_https_traffic_only       = true     #Require secure transfer (HTTPS) to the storage account for REST API Operations
  min_tls_version                 = "TLS1_2" #Configure the minimum required version of Transport Layer Security (TLS) for a storage account and require TLS Version1.2
  is_hns_enabled                  = true     #Enables Hierachical namespace, enabling SFTP
  sftp_enabled                    = false
  public_network_access_enabled   = false

  tags = local.base_tags
  lifecycle { ignore_changes = [tags["BuiltOn"]] }
}
resource "azurerm_storage_account_network_rules" "drop_st_nr" {
  # Prevents locking the Storage Account before all resources are created
  depends_on = [
    azurerm_storage_account.drop_st
  ]

  storage_account_id         = azurerm_storage_account.drop_st.id
  default_action             = "Deny"
  ip_rules                   = []
  virtual_network_subnet_ids = []
  bypass                     = ["None"]
}
resource "azurerm_storage_container" "mft_drop" {
  name                  = "mft-drop"
  storage_account_name  = azurerm_storage_account.drop_st.name
  container_access_type = "private"
}
module "drop_st_local_pe" {
  source     = "../../terraform-modules/pe"
  depends_on = [azurerm_private_dns_zone_virtual_network_link.this]

  resource_id         = azurerm_storage_account.drop_st.id
  resource_group_name = module.mainregion_poc_rg.name
  location            = module.mainregion_poc_rg.location

  subnet_id            = azurerm_subnet.pe_subnet.id
  subresource_names    = ["blob"]
  is_manual_connection = false

  privdns_rg_name = module.mainregion_poc_rg.name
  cname_zone      = "blob.core.windows.net"
  a_zone          = "privatelink.blob.core.windows.net"
  ttl             = 10

  tags = local.base_tags
}
module "drop_st_external_pe" {
  providers = { azurerm = azurerm.external }
  source    = "../../terraform-modules/pe"

  resource_id = azurerm_storage_account.drop_st.id

  resource_group_name  = data.azurerm_subnet.external_subnet.resource_group_name
  location             = data.azurerm_virtual_network.external_vnet.location
  subnet_id            = data.azurerm_subnet.external_subnet.id
  subresource_names    = ["blob"]
  is_manual_connection = false

  privdns_rg_name = data.azurerm_subnet.external_subnet.resource_group_name
  cname_zone      = "blob.core.windows.net"
  a_zone          = "privatelink.blob.core.windows.net"
  ttl             = 10

  tags = local.base_tags
}

#   / Archive Storage
resource "azurerm_storage_account" "archive_st" {
  name                = lower(replace("st-${local.full_suffix}-archive", "-", ""))
  resource_group_name = module.mainregion_poc_rg.name
  location            = module.mainregion_poc_rg.location

  account_kind             = "StorageV2"
  account_tier             = "Standard"
  account_replication_type = "ZRS"

  allow_nested_items_to_be_public = false    #Disable anonymous public read access to containers and blobs
  enable_https_traffic_only       = true     #Require secure transfer (HTTPS) to the storage account for REST API Operations
  min_tls_version                 = "TLS1_2" #Configure the minimum required version of Transport Layer Security (TLS) for a storage account and require TLS Version1.2
  is_hns_enabled                  = false
  sftp_enabled                    = false
  public_network_access_enabled   = false

  tags = local.base_tags
  lifecycle { ignore_changes = [tags["BuiltOn"]] }
}
resource "azurerm_storage_account_network_rules" "archive_st_nr" {
  # Prevents locking the Storage Account before all resources are created
  depends_on = [
    azurerm_storage_account.archive_st
  ]

  storage_account_id         = azurerm_storage_account.archive_st.id
  default_action             = "Deny"
  ip_rules                   = []
  virtual_network_subnet_ids = []
  bypass                     = ["None"]
}
resource "azurerm_storage_container" "cy_container" {
  name                  = "2023-archives"
  storage_account_name  = azurerm_storage_account.archive_st.name
  container_access_type = "private"
}
resource "azurerm_storage_container" "andet_container" {
  name                  = "anomaly-data"
  storage_account_name  = azurerm_storage_account.archive_st.name
  container_access_type = "private"
}
module "archive_st_local_pe" {
  source     = "../../terraform-modules/pe"
  depends_on = [azurerm_private_dns_zone_virtual_network_link.this]

  resource_id         = azurerm_storage_account.archive_st.id
  resource_group_name = module.mainregion_poc_rg.name
  location            = module.mainregion_poc_rg.location

  subnet_id            = azurerm_subnet.pe_subnet.id
  subresource_names    = ["blob"]
  is_manual_connection = false

  privdns_rg_name = module.mainregion_poc_rg.name
  cname_zone      = "blob.core.windows.net"
  a_zone          = "privatelink.blob.core.windows.net"
  ttl             = 10

  tags = local.base_tags
}
module "archive_st_external_pe" {
  providers = { azurerm = azurerm.external }
  source    = "../../terraform-modules/pe"

  resource_id = azurerm_storage_account.archive_st.id

  resource_group_name  = data.azurerm_subnet.external_subnet.resource_group_name
  location             = data.azurerm_virtual_network.external_vnet.location
  subnet_id            = data.azurerm_subnet.external_subnet.id
  subresource_names    = ["blob"]
  is_manual_connection = false

  privdns_rg_name = data.azurerm_subnet.external_subnet.resource_group_name
  cname_zone      = "blob.core.windows.net"
  a_zone          = "privatelink.blob.core.windows.net"
  ttl             = 10

  tags = local.base_tags
}

#   / Web App + Function App Storage
resource "azurerm_storage_account" "app_svc_st" {
  name                = substr(lower(replace("st-${local.full_suffix}-appsvc-support", "-", "")), 0, 24)
  resource_group_name = module.mainregion_poc_rg.name
  location            = module.mainregion_poc_rg.location

  account_kind             = "StorageV2"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public = false    #Disable anonymous public read access to containers and blobs
  enable_https_traffic_only       = true     #Require secure transfer (HTTPS) to the storage account for REST API Operations
  min_tls_version                 = "TLS1_2" #Configure the minimum required version of Transport Layer Security (TLS) for a storage account and require TLS Version1.2
  is_hns_enabled                  = false
  sftp_enabled                    = false
  public_network_access_enabled   = false

  tags = local.base_tags
  lifecycle { ignore_changes = [tags["BuiltOn"]] }
}
resource "azurerm_storage_account_network_rules" "app_svc_st_nr" {
  # Prevents locking the Storage Account before all resources are created
  depends_on = [
    azurerm_storage_account.app_svc_st
  ]

  storage_account_id         = azurerm_storage_account.app_svc_st.id
  default_action             = "Deny"
  ip_rules                   = []
  virtual_network_subnet_ids = []
  bypass                     = ["None"]
}
resource "azurerm_storage_container" "winwebapp_logs_container" {
  name                  = "win-web-app-logs"
  storage_account_name  = azurerm_storage_account.app_svc_st.name
  container_access_type = "private"
}
module "app_svc_st_local_pe" {
  source     = "../../terraform-modules/pe"
  depends_on = [azurerm_private_dns_zone_virtual_network_link.this]

  resource_id         = azurerm_storage_account.app_svc_st.id
  resource_group_name = module.mainregion_poc_rg.name
  location            = module.mainregion_poc_rg.location

  subnet_id            = azurerm_subnet.pe_subnet.id
  subresource_names    = ["blob"]
  is_manual_connection = false

  privdns_rg_name = module.mainregion_poc_rg.name
  cname_zone      = "blob.core.windows.net"
  a_zone          = "privatelink.blob.core.windows.net"
  ttl             = 10

  tags = local.base_tags
}
module "app_svc_st_external_pe" {
  providers = { azurerm = azurerm.external }
  source    = "../../terraform-modules/pe"

  resource_id = azurerm_storage_account.app_svc_st.id

  resource_group_name  = data.azurerm_subnet.external_subnet.resource_group_name
  location             = data.azurerm_virtual_network.external_vnet.location
  subnet_id            = data.azurerm_subnet.external_subnet.id
  subresource_names    = ["blob"]
  is_manual_connection = false

  privdns_rg_name = data.azurerm_subnet.external_subnet.resource_group_name
  cname_zone      = "blob.core.windows.net"
  a_zone          = "privatelink.blob.core.windows.net"
  ttl             = 10

  tags = local.base_tags
}

#--------------------------------------------------------------
#   Anomaly Detector AI
#--------------------------------------------------------------
resource "azurerm_cognitive_account" "anomaly_detector" {
  name                = lower("andetect-${local.full_suffix}")
  resource_group_name = module.mainregion_poc_rg.name
  location            = module.mainregion_poc_rg.location

  kind                          = "AnomalyDetector"
  custom_subdomain_name         = lower("andetect-${local.full_suffix}")
  dynamic_throttling_enabled    = false
  fqdns                         = []
  sku_name                      = "S0"
  public_network_access_enabled = false

  network_acls {
    default_action = "Deny"
    ip_rules       = []
  }
}
module "anomaly_detector_local_pe" {
  source = "../../terraform-modules/pe"

  depends_on = [azurerm_private_dns_zone_virtual_network_link.this]

  resource_id         = azurerm_cognitive_account.anomaly_detector.id
  resource_group_name = module.mainregion_poc_rg.name
  location            = module.mainregion_poc_rg.location

  subnet_id            = azurerm_subnet.pe_subnet.id
  subresource_names    = ["account"]
  is_manual_connection = false

  privdns_rg_name = module.mainregion_poc_rg.name
  cname_zone      = null
  a_zone          = "cognitiveservices.azure.com"
  ttl             = 10

  tags = local.base_tags
}

#--------------------------------------------------------------
#   Key vault
#--------------------------------------------------------------
resource "azurerm_key_vault" "kv" {
  name                      = lower("kv-${local.full_suffix}")
  resource_group_name       = module.mainregion_poc_rg.name
  location                  = module.mainregion_poc_rg.location
  tenant_id                 = data.azurerm_client_config.current.tenant_id
  enable_rbac_authorization = true
  sku_name                  = "standard"
  # soft_delete_enabled             = true # Disabling Soft Delete is not allowed anymore as of 2020-12-15
  purge_protection_enabled        = false
  enabled_for_disk_encryption     = false
  enabled_for_template_deployment = false
  enabled_for_deployment          = false

  network_acls {
    bypass         = "AzureServices"
    default_action = "Deny"
    ip_rules       = [] # [module.publicip.public_ip]
    # virtual_network_subnet_ids = var.virtual_network_subnet_ids
  }

  tags = local.base_tags
  lifecycle { ignore_changes = [tags["BuiltOn"]] }
}
resource "azurerm_role_assignment" "terraform_role_to_kv_assignment" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azurerm_client_config.current.object_id
}
module "kv_local_pe" {
  source = "../../terraform-modules/pe"

  depends_on = [azurerm_private_dns_zone_virtual_network_link.this]

  resource_id         = azurerm_key_vault.kv.id
  resource_group_name = module.mainregion_poc_rg.name
  location            = module.mainregion_poc_rg.location

  subnet_id            = azurerm_subnet.pe_subnet.id
  subresource_names    = ["vault"]
  is_manual_connection = false

  privdns_rg_name = module.mainregion_poc_rg.name
  cname_zone      = "vault.azure.net"
  a_zone          = "vaultcore.azure.net"
  ttl             = 10

  tags = local.base_tags
}

#--------------------------------------------------------------
#   Application Service (Service Plan + Windows Web App)
#--------------------------------------------------------------
#   / Main region App Service
resource "azurerm_service_plan" "poc_app_svc_plan" {
  name                = lower("appsvcplan-win-${local.full_suffix}")
  resource_group_name = module.mainregion_poc_rg.name
  location            = module.mainregion_poc_rg.location
  os_type             = "Windows"
  sku_name            = "S1"
  tags                = local.base_tags
}
#   / Windows Web App
resource "azurerm_windows_web_app" "poc_app_svc" {
  name                = lower("webapp-win-${local.full_suffix}")
  resource_group_name = module.mainregion_poc_rg.name
  location            = module.mainregion_poc_rg.location
  service_plan_id     = azurerm_service_plan.poc_app_svc_plan.id

  public_network_access_enabled = false
  virtual_network_subnet_id     = azurerm_subnet.appsvc_int_subnet.id

  identity {
    type = "SystemAssigned"
  }

  site_config {
    vnet_route_all_enabled   = true
    use_32_bit_worker        = false
    remote_debugging_enabled = false
    application_stack {
      current_stack  = "dotnetcore"
      dotnet_version = "v6.0"
      # dotnet_core_version = "v6.0"
    }
  }
  connection_string {
    name  = "WebApp1EfDbContext-MI"
    type  = "SQLServer"
    value = "Server=tcp:${azurerm_mssql_server.poc_sql_server.name}.database.windows.net,1433;Authentication=Active Directory Default;Database=${azurerm_mssql_database.poc_sql_db.name};"
  }

  auth_settings_v2 {
    auth_enabled             = true
    default_provider         = "azureactivedirectory"
    excluded_paths           = []
    forward_proxy_convention = "NoProxy"
    http_route_api_prefix    = "/.auth"
    require_authentication   = true
    require_https            = true
    runtime_version          = "~1"
    unauthenticated_action   = "RedirectToLoginPage"

    active_directory_v2 {
      allowed_applications = []
      allowed_audiences = [
        "api://${azuread_application.azsp_app.application_id}",
      ]
      allowed_groups                  = []
      allowed_identities              = []
      client_id                       = azuread_application.azsp_app.application_id
      client_secret_setting_name      = "MICROSOFT_PROVIDER_AUTHENTICATION_SECRET"
      jwt_allowed_client_applications = []
      jwt_allowed_groups              = []
      login_parameters                = {}
      tenant_auth_endpoint            = "https://sts.windows.net/${var.tenant_id}/v2.0"
      www_authentication_disabled     = false
    }

    login {
      allowed_external_redirect_urls    = []
      cookie_expiration_convention      = "FixedTime"
      cookie_expiration_time            = "08:00:00"
      nonce_expiration_time             = "00:05:00"
      preserve_url_fragments_for_logins = false
      token_refresh_extension_time      = 72
      token_store_enabled               = true
      validate_nonce                    = true
    }
  }

  app_settings = {
    # App Insights settings
    "APPINSIGHTS_INSTRUMENTATIONKEY"                  = azurerm_application_insights.poc_appins.instrumentation_key
    "APPINSIGHTS_PROFILERFEATURE_VERSION"             = "1.0.0"
    "APPINSIGHTS_SNAPSHOTFEATURE_VERSION"             = "1.0.0"
    "APPLICATIONINSIGHTS_CONNECTION_STRING"           = azurerm_application_insights.poc_appins.connection_string
    "ApplicationInsightsAgent_EXTENSION_VERSION"      = "~2"
    "DiagnosticServices_EXTENSION_VERSION"            = "~3"
    "InstrumentationEngine_EXTENSION_VERSION"         = "disabled"
    "SnapshotDebugger_EXTENSION_VERSION"              = "disabled"
    "XDT_MicrosoftApplicationInsights_BaseExtensions" = "disabled"
    "XDT_MicrosoftApplicationInsights_Java"           = "disabled"
    "XDT_MicrosoftApplicationInsights_Mode"           = "recommended"
    "XDT_MicrosoftApplicationInsights_NodeJS"         = "disabled"
    "XDT_MicrosoftApplicationInsights_PreemptSdk"     = "disabled"

    # Authentication
    "MICROSOFT_PROVIDER_AUTHENTICATION_SECRET" = azuread_application_password.azsp_app_pwd.value

    # Drop Storage Account / Container
    "DropStorageAccountName" = azurerm_storage_account.drop_st.name
    "DropContainerName"      = azurerm_storage_container.mft_drop.name

    # Archive Storage Account / Container
    "ArchiveStorageAccountName" = azurerm_storage_account.archive_st.name
    "ArchiveContainerName"      = azurerm_storage_container.cy_container.name

    # Anomaly Detector
    "ArchiveAnDetContainerName" = azurerm_storage_container.andet_container.name
    "ArchiveAnDetBlobName"      = "request-data.csv"
    "AnDetEndpoint"             = azurerm_cognitive_account.anomaly_detector.endpoint
    "AnDetKey"                  = azurerm_cognitive_account.anomaly_detector.primary_access_key
  }

  sticky_settings {
    app_setting_names = [
      "APPINSIGHTS_INSTRUMENTATIONKEY",
      "APPLICATIONINSIGHTS_CONNECTION_STRING ",
      "APPINSIGHTS_PROFILERFEATURE_VERSION",
      "APPINSIGHTS_SNAPSHOTFEATURE_VERSION",
      "ApplicationInsightsAgent_EXTENSION_VERSION",
      "XDT_MicrosoftApplicationInsights_BaseExtensions",
      "DiagnosticServices_EXTENSION_VERSION",
      "InstrumentationEngine_EXTENSION_VERSION",
      "SnapshotDebugger_EXTENSION_VERSION",
      "XDT_MicrosoftApplicationInsights_Mode",
      "XDT_MicrosoftApplicationInsights_PreemptSdk",
      "APPLICATIONINSIGHTS_CONFIGURATION_CONTENT",
      "XDT_MicrosoftApplicationInsightsJava",
      "XDT_MicrosoftApplicationInsights_NodeJS",
      "MICROSOFT_PROVIDER_AUTHENTICATION_SECRET",
    ]
  }

  logs {
    detailed_error_messages = false
    failed_request_tracing  = false
    application_logs {
      file_system_level = "Information"
    }
    http_logs {
      file_system {
        retention_in_days = 0
        retention_in_mb   = 35
      }
    }
  }

  # Adding this ignore_changes to pass a bug confusing at each plan:
  #   dotnet_core_version and dotnet_version
  lifecycle { ignore_changes = [site_config[0].application_stack] }

  tags = local.base_tags
}
#   / Private Endpoint for External incoming connections
module "appsvc_external_pe" {
  providers = { azurerm = azurerm.external }
  source    = "../../terraform-modules/pe"

  resource_id = azurerm_windows_web_app.poc_app_svc.id

  resource_group_name  = data.azurerm_subnet.external_subnet.resource_group_name
  location             = data.azurerm_virtual_network.external_vnet.location
  subnet_id            = data.azurerm_subnet.external_subnet.id
  subresource_names    = ["sites"]
  is_manual_connection = false

  privdns_rg_name = data.azurerm_subnet.external_subnet.resource_group_name
  cname_zone      = "azurewebsites.net"
  a_zone          = "privatelink.azurewebsites.net"
  ttl             = 10

  tags = local.base_tags
}
#   / Private DNS entry for SCM for External incoming connections
module "appsvc_scm_external_privdns" {
  source    = "../../terraform-modules/pe-dns"
  providers = { azurerm = azurerm.external }

  record_name        = "${azurerm_windows_web_app.poc_app_svc.name}.scm"
  private_ip_address = module.appsvc_external_pe.private_ip_address
  privdns_rg_name    = data.azurerm_subnet.external_subnet.resource_group_name
  cname_zone         = "azurewebsites.net"
  a_zone             = "privatelink.azurewebsites.net"
  ttl                = 10

  tags = local.base_tags
}

#   / Role Assignment for Win Web App MSI on Drop Storage
resource "azurerm_role_assignment" "webapp_msi_drop_st_blob_contributor" {
  principal_id         = azurerm_windows_web_app.poc_app_svc.identity[0].principal_id
  role_definition_name = "Storage Blob Data Contributor"
  scope                = azurerm_storage_account.drop_st.id
}
#   / Role Assignment for Win Web App MSI on Archive Storage
resource "azurerm_role_assignment" "webapp_msi_archive_st_blob_contributor" {
  principal_id         = azurerm_windows_web_app.poc_app_svc.identity[0].principal_id
  role_definition_name = "Storage Blob Data Contributor"
  scope                = azurerm_storage_account.archive_st.id
}
#   / Role Assignment for Win Web App MSI on Web App + Function App Storage
resource "azurerm_role_assignment" "webapp_msi_app_svc_st_blob_contributor" {
  principal_id         = azurerm_windows_web_app.poc_app_svc.identity[0].principal_id
  role_definition_name = "Storage Blob Data Contributor"
  scope                = azurerm_storage_account.app_svc_st.id
}

#     ========  WIN WEB APP POST DEPLOYMENT STEPS  ========

# 1. To grant Win Web App's MSI access to the SQL Database, execute this T-SQL, logged with an Azure AD user:
# CREATE USER ["${azurerm_windows_web_app.poc_app_svc.name}"] FROM EXTERNAL PROVIDER;
# ALTER ROLE db_datareader ADD MEMBER ["${azurerm_windows_web_app.poc_app_svc.name}"];
# ALTER ROLE db_datawriter ADD MEMBER ["${azurerm_windows_web_app.poc_app_svc.name}"];
# ALTER ROLE db_ddladmin ADD MEMBER ["${azurerm_windows_web_app.poc_app_svc.name}"];
# GO

# 2. To publish Web Deploy from Visual Studio, enable:
#    Configuration / General Settings / Basic Auth Publishing Credentials to "On"  / Save (Defaults to "Off" and the setting is not accessible to terraform)

# 3. Publish the Application from Visual Studio (or CD Pipeline)

# 4. Upload request-data.csv in the the "anomaly-data" container of the Archive Storage Account
#    Source file is here: https://raw.githubusercontent.com/Azure/azure-sdk-for-python/main/sdk/anomalydetector/azure-ai-anomalydetector/samples/sample_data/request-data.csv

#--------------------------------------------------------------
#   Azure Function App
#--------------------------------------------------------------
resource "azurerm_windows_function_app" "win_func_app" {
  name                = lower("func-app-${local.full_suffix}")
  resource_group_name = module.mainregion_poc_rg.name
  location            = module.mainregion_poc_rg.location

  storage_account_name = azurerm_storage_account.app_svc_st.name
  # storage_account_access_key    = azurerm_storage_account.app_svc_st.primary_access_key
  storage_uses_managed_identity = true
  service_plan_id               = azurerm_service_plan.poc_app_svc_plan.id

  public_network_access_enabled = false
  virtual_network_subnet_id     = azurerm_subnet.appsvc_int_subnet.id

  identity {
    type = "SystemAssigned"
  }

  site_config {
    vnet_route_all_enabled   = true
    use_32_bit_worker        = false
    remote_debugging_enabled = false
    application_stack {
      use_dotnet_isolated_runtime = false
      dotnet_version              = "v6.0"
    }
    application_insights_connection_string = azurerm_application_insights.poc_appins.connection_string
    application_insights_key               = azurerm_application_insights.poc_appins.instrumentation_key
  }
  connection_string {
    name  = "WebApp1EfDbContext-MI"
    type  = "SQLServer"
    value = "Server=tcp:${azurerm_mssql_server.poc_sql_server.name}.database.windows.net,1433;Authentication=Active Directory Default;Database=${azurerm_mssql_database.poc_sql_db.name};"
  }

  app_settings = {
    # Azure Function App required storage
    "AzureWebJobsStorage"                = azurerm_storage_account.app_svc_st.primary_blob_connection_string
    "AZURE_STORAGEBLOB_RESOURCEENDPOINT" = azurerm_storage_account.app_svc_st.primary_blob_connection_string
    "WEBSITE_RUN_FROM_PACKAGE"           = "1"

    # App Insights settings
    "APPINSIGHTS_INSTRUMENTATIONKEY"                  = azurerm_application_insights.poc_appins.instrumentation_key
    "APPINSIGHTS_PROFILERFEATURE_VERSION"             = "1.0.0"
    "APPINSIGHTS_SNAPSHOTFEATURE_VERSION"             = "1.0.0"
    "APPLICATIONINSIGHTS_CONNECTION_STRING"           = azurerm_application_insights.poc_appins.connection_string
    "ApplicationInsightsAgent_EXTENSION_VERSION"      = "~2"
    "DiagnosticServices_EXTENSION_VERSION"            = "~3"
    "InstrumentationEngine_EXTENSION_VERSION"         = "disabled"
    "SnapshotDebugger_EXTENSION_VERSION"              = "disabled"
    "XDT_MicrosoftApplicationInsights_BaseExtensions" = "disabled"
    "XDT_MicrosoftApplicationInsights_Java"           = "disabled"
    "XDT_MicrosoftApplicationInsights_Mode"           = "recommended"
    "XDT_MicrosoftApplicationInsights_NodeJS"         = "disabled"
    "XDT_MicrosoftApplicationInsights_PreemptSdk"     = "disabled"

    # Drop Storage Account / Container
    "DropStorageAccountName" = azurerm_storage_account.drop_st.name
    "DropContainerName"      = azurerm_storage_container.mft_drop.name

    # Archive Storage Account / Container
    "ArchiveStorageAccountName" = azurerm_storage_account.archive_st.name
    "ArchiveContainerName"      = azurerm_storage_container.cy_container.name

    # Functions Enable/Disable
    "AzureWebJobs.InputFilesProcessor.Disabled" = "1"
    "AzureWebJobs.WhatIsMyIP.Disabled"          = "1"
  }

  sticky_settings {
    app_setting_names = [
      "APPINSIGHTS_INSTRUMENTATIONKEY",
      "APPLICATIONINSIGHTS_CONNECTION_STRING ",
      "APPINSIGHTS_PROFILERFEATURE_VERSION",
      "APPINSIGHTS_SNAPSHOTFEATURE_VERSION",
      "ApplicationInsightsAgent_EXTENSION_VERSION",
      "XDT_MicrosoftApplicationInsights_BaseExtensions",
      "DiagnosticServices_EXTENSION_VERSION",
      "InstrumentationEngine_EXTENSION_VERSION",
      "SnapshotDebugger_EXTENSION_VERSION",
      "XDT_MicrosoftApplicationInsights_Mode",
      "XDT_MicrosoftApplicationInsights_PreemptSdk",
      "APPLICATIONINSIGHTS_CONFIGURATION_CONTENT",
      "XDT_MicrosoftApplicationInsightsJava",
      "XDT_MicrosoftApplicationInsights_NodeJS",
      "AZURE_STORAGEBLOB_RESOURCEENDPOINT",
    ]
  }

  tags = local.base_tags
}
module "function_external_pe" {
  providers = { azurerm = azurerm.external }
  source    = "../../terraform-modules/pe"

  resource_id = azurerm_windows_function_app.win_func_app.id

  resource_group_name  = data.azurerm_subnet.external_subnet.resource_group_name
  location             = data.azurerm_virtual_network.external_vnet.location
  subnet_id            = data.azurerm_subnet.external_subnet.id
  subresource_names    = ["sites"]
  is_manual_connection = false

  privdns_rg_name = data.azurerm_subnet.external_subnet.resource_group_name
  cname_zone      = "azurewebsites.net"
  a_zone          = "privatelink.azurewebsites.net"
  ttl             = 10

  tags = local.base_tags
}
module "function_scm_external_privdns" {
  source    = "../../terraform-modules/pe-dns"
  providers = { azurerm = azurerm.external }

  record_name        = "${azurerm_windows_function_app.win_func_app.name}.scm"
  private_ip_address = module.function_external_pe.private_ip_address

  privdns_rg_name = data.azurerm_subnet.external_subnet.resource_group_name
  cname_zone      = "azurewebsites.net"
  a_zone          = "privatelink.azurewebsites.net"
  ttl             = 10

  tags = local.base_tags
}
resource "azurerm_role_assignment" "function_role_to_app_svc_st_assignment" {
  principal_id         = azurerm_windows_function_app.win_func_app.identity[0].principal_id
  role_definition_name = "Storage Blob Data Contributor"
  scope                = azurerm_storage_account.app_svc_st.id
}

#   / Role Assignment for Win Web App MSI on Drop Storage
resource "azurerm_role_assignment" "funcapp_msi_drop_st_blob_contributor" {
  principal_id         = azurerm_windows_function_app.win_func_app.identity[0].principal_id
  role_definition_name = "Storage Blob Data Contributor"
  scope                = azurerm_storage_account.drop_st.id
}
#   / Role Assignment for Win Web App MSI on Archive Storage
resource "azurerm_role_assignment" "funcapp_msi_archive_st_blob_contributor" {
  principal_id         = azurerm_windows_function_app.win_func_app.identity[0].principal_id
  role_definition_name = "Storage Blob Data Contributor"
  scope                = azurerm_storage_account.archive_st.id
}
#   / Role Assignment for Win Web App MSI on Web App + Function App Storage
# resource "azurerm_role_assignment" "funcapp_msi_app_svc_st_blob_contributor" {
#   principal_id         = azurerm_windows_function_app.win_func_app.identity[0].principal_id
#   role_definition_name = "Storage Blob Data Contributor"
#   scope                = azurerm_storage_account.app_svc_st.id
# }

#     ========  FUNCTION APP POST DEPLOYMENT STEPS  ========

# 1. To grant Function App's MSI access to the SQL Database, execute this T-SQL, logged with an Azure AD user:
# CREATE USER ["${azurerm_windows_function_app.win_func_app.name}"] FROM EXTERNAL PROVIDER;
# ALTER ROLE db_datareader ADD MEMBER ["${azurerm_windows_function_app.win_func_app.name}"];
# ALTER ROLE db_datawriter ADD MEMBER ["${azurerm_windows_function_app.win_func_app.name}"];
# ALTER ROLE db_ddladmin ADD MEMBER ["${azurerm_windows_function_app.win_func_app.name}"];
# GO

# 2. To publish from Visual Studio, enable:
#    Configuration / General Settings / Basic Auth Publishing Credentials to "On"  / Save (Defaults to "Off" and the setting is not accessible to terraform)

# 3. Publish the Function from Visual Studio (or CD Pipeline)

# 4. Upload the files that are in the 'data' directory in the "mft-drop" container of the Drop Storage Account


#*/
