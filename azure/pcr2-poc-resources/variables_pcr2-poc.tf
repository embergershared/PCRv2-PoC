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

# SFTP Connection
variable "sftp_user_name" {}
variable "sftp_user_pwd" {}