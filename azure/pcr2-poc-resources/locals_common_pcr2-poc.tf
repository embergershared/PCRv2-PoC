
#--------------------------------------------------------------
#   Plan's Locals and specific resources
#--------------------------------------------------------------
data "azurerm_client_config" "current" {}
resource "time_static" "this" {}
locals {
  # Plan Tag value
  tf_plan = "/azure/pcr2-poc-resources/main_pcr2-poc.tf"

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
