environment = "prod"

# AWS Configs
region = "us-west-2"

# HashiCorp Vault Configs
vault_address = "http://vault.internal.levantine.io:8200"
# NOTE: passed in via -var "vault_token=${VAULT_TOKEN}" from the GitHub
# Actions secret at deploy time, matching thisper's convention -- never
# committed here.

# Hosted zone ID of the root account for subdomain delegation for this account
levantine_io_hosted_zone_id = "Z32CDTOFAQVLJJ"
