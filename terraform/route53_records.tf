data "aws_instance" "bastion_instance" {
  filter {
    name   = "tag:Name"
    values = ["Bastion"]
  }
}

data "aws_route53_zone" "local_env_levantine_io" {
  name = "${var.environment}.levantine.io."
}

resource "aws_route53_record" "configure_bastion_r53_record_levantine_io" {
  zone_id = data.aws_route53_zone.local_env_levantine_io.zone_id
  name    = "livecam.${var.environment}.levantine.io"
  type    = "A"
  ttl     = 300
  records = [data.aws_instance.bastion_instance.public_ip]
}

# LAN-only address for home viewing. Deliberately a private IP in public
# DNS: that is what lets phones and DoH browsers -- which never consult the
# local resolver -- resolve straight to the LAN with no client config, so
# home traffic never leaves the house and incurs no AWS egress.
#
# Requires a matching OPNsense Unbound host override as well: rebind
# protection discards private addresses returned from public DNS, so
# clients that DO use the local resolver get NXDOMAIN from this record
# alone. Both halves are needed to cover every client.
#
# Covered by the existing *.levantine.io wildcard cert because the name is
# flat; a livecam.local.levantine.io form would have needed a new cert,
# since a wildcard matches only one label.
resource "aws_route53_record" "livecam_lan" {
  provider = aws.delegate
  zone_id  = var.levantine_io_hosted_zone_id
  name     = "livecam-lan.levantine.io"
  type     = "A"
  ttl      = 300
  records  = ["192.168.1.31"]
}
