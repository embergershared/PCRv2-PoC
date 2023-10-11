# Get public IP
#provider http {}
# https://registry.terraform.io/providers/hashicorp/http/latest/docs/data-sources/http

data http icanhazip {
  url = "http://icanhazip.com"
}