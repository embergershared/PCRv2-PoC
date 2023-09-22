locals {
  target_resource_name = split("/", var.resource_id)[8]
  vnet_name            = split("/", var.subnet_id)[8]
  subnet_name          = split("/", var.subnet_id)[10]
}

#     / Create Private Endpoint
resource "azurerm_private_endpoint" "this" {
  name                          = "pe-to-${replace(local.target_resource_name, "-", "")}"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  subnet_id                     = var.subnet_id
  custom_network_interface_name = "nic-pe-to-${replace(local.target_resource_name, "-", "")}"

  private_service_connection {
    name                           = "${local.vnet_name}_${local.subnet_name}_connection"
    private_connection_resource_id = var.resource_id
    subresource_names              = var.subresource_names
    is_manual_connection           = var.is_manual_connection
    request_message                = var.is_manual_connection ? "Please approve this PE connection to ${local.vnet_name}/${local.subnet_name}." : null
  }

  tags = var.tags
}

#     / Create Private DNS records for Private Endpoint
module "pe-dns" {
  source = "../pe-dns"

  record_name        = local.target_resource_name
  private_ip_address = azurerm_private_endpoint.this.private_service_connection[0].private_ip_address
  privdns_rg_name    = var.privdns_rg_name
  cname_zone         = var.cname_zone
  a_zone             = var.a_zone
  ttl                = var.ttl
  tags               = var.tags
}
