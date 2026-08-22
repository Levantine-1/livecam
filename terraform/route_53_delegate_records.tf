data "vault_generic_secret" "aws_delegation_creds" {
  path = "kv/aws/iam_access_keys/subdomain_delegation"
}

provider "aws" {
  # NOTE: The delegation account is used for DNS subdomain delegation between the root account and the subdomain account
  alias = "delegate"
  region = var.region
  access_key = try(data.vault_generic_secret.aws_delegation_creds.data["access_key"], null)
  secret_key = try(data.vault_generic_secret.aws_delegation_creds.data["secret_key"], null)
}

resource "aws_route53_record" "configure_delegate_record" {
  provider = aws.delegate
  zone_id = var.levantine_io_hosted_zone_id
  name    = "livecam.levantine.io"
  type    = "A"
  ttl     = 300
  records = [data.aws_instance.bastion_instance.public_ip]
}
