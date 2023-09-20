variable "resource_id" {}
variable "resource_group_name" {}
variable "location" { description = "The private endpoint must be created in the same region than the vnet/subnet it attaches to." }
variable "subnet_id" {}
variable "subresource_names" { description = "The list can be found here: https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview#private-link-resource" }
variable "is_manual_connection" { default = true }
variable "privdns_rg_name" {}
variable "cname_zone" { default = null }
variable "a_zone" { default = null }
variable "ttl" { default = 3600 }
variable "tags" {}
