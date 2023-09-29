#
# Copyright 2022 Emmanuel Bergerat
#

output "id" {
  value       = azurerm_resource_group.this.id
  description = "Resource group Id."
}
output "name" {
  value       = azurerm_resource_group.this.name
  description = "Resource group name."
}
output "location" {
  value       = azurerm_resource_group.this.location
  description = "Resource group location."
}
output "tags" {
  value       = azurerm_resource_group.this.tags
  description = "Resource group tags."
}
output "random_suffix" {
  value       = module.rg_name.random_suffix
  description = "Randomized piece of the Resource group name when \"`add_random = true`\"."
}
