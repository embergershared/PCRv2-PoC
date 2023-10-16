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
variable "external_snet_pe_id" {}

# Azure SQL Server admin
variable "az_sql_admin_login" {}
variable "az_sql_admin_object_id" {}

# SFTP Connection
variable "sftp_user_name" {}
variable "sftp_user_pwd" {}

# External facing Web App URL
variable "external_url" { default = null }
variable "tls_cert_path" { default = null }
variable "tls_cert_pwd" { default = null }
