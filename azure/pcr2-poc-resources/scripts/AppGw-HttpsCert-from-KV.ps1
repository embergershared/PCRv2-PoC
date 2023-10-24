# Ref: https://learn.microsoft.com/en-us/azure/application-gateway/key-vault-certs?WT.mc_id=Portal-Microsoft_Azure_HybridNetworking#key-vault-azure-role-based-access-control-permission-model

# Why: Specifying Azure Key Vault certificates that are subject to the role-based access control permission model is not supported via the portal.

# To execute these commands:
# - Use Cloud shell PowerShell: there's a bug with Az.PowerShell when executing Get-AzApplicationGateway locally ...
# - It will required to disable Key vault Networking restrictions to allow Cloud shell access to KV

# Connect to Subscription
Connect-AzAccount
Get-AzSubscription
Set-AzContext -Subscription "<Id>"

# Get the Application Gateway we want to modify
$appgw = Get-AzApplicationGateway -Name "appgw-waf-use2-s4-pcr2-poc" -ResourceGroupName "rg-use2-s4-pcr2-poc"

# Specify the resource id to the user assigned managed identity - This can be found by going to the properties of the managed identity
Set-AzApplicationGatewayIdentity -ApplicationGateway $appgw -UserAssignedIdentityId "/subscriptions/ABC-DEF-GHI/resourcegroups/JKL-MNO/providers/Microsoft.ManagedIdentity/userAssignedIdentities/msi-appgw-waf-use2-s4-pcr2-poc"

# Get the secret ID from Key Vault
$secret = Get-AzKeyVaultSecret -VaultName "kv-use2-s4-pcr2-poc" -Name "pcr2-poc-tls-cert-kv"
$secretId = $secret.Id.Replace($secret.Version, "") # Remove the secret version so AppGW will use the latest version in future syncs

# Specify the secret ID from Key Vault 
Add-AzApplicationGatewaySslCertificate -KeyVaultSecretId $secretId -ApplicationGateway $appgw -Name $secret.Name

# Commit the changes to the Application Gateway
Set-AzApplicationGateway -ApplicationGateway $appgw