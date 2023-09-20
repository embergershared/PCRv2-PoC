#     / Create CNAME record for Private endpoint
resource "azurerm_private_dns_cname_record" "this" {
  count = var.cname_zone != null ? 1 : 0

  name                = var.record_name
  zone_name           = var.cname_zone
  resource_group_name = var.privdns_rg_name
  ttl                 = var.ttl
  record              = "${var.record_name}.${var.a_zone}"
  tags                = var.tags
}
#     / Create A record for Private endpoint
resource "azurerm_private_dns_a_record" "this" {
  count = var.a_zone != null ? 1 : 0

  name                = var.record_name
  zone_name           = var.a_zone
  resource_group_name = var.privdns_rg_name
  ttl                 = var.ttl
  records             = ["${var.private_ip_address}"]
  tags                = var.tags
}
