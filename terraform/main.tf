terraform {
  backend "s3" {
    bucket       = "prod-levantine-terraform-bucket"
    key          = "livecam/terraform.tfstate"
    region       = "us-west-2"
    use_lockfile = true
  }
}

variable "region" {}
variable "environment" {}
variable "vault_address" {}
variable "vault_token" {}
variable "levantine_io_hosted_zone_id" {}

# Only used by route_53_delegate_records.tf's aws.delegate provider, to
# read the subdomain-delegation account's AWS credentials -- unlike
# thisper, this repo has no terraform-managed Vault *write* (livecam's own
# app secret, kv/data/livecam/admin, is set up once via ansible's
# configure_vault_auth.yml, not generated/written by this terraform).
provider "vault" {
  address = var.vault_address
  token   = var.vault_token
  skip_child_token = true
}

# Auth for the default (non-delegate) AWS provider is via GitHub Actions
# OIDC role assumption (see iam_oidc_role.tf), not a long-lived
# Vault-stored static key.
provider "aws" {
  region = var.region
}
