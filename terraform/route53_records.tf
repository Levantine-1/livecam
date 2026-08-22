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
# 10.69.69.133 is `service`'s home-LAN interface, NOT dockerhost1. This
# record originally pointed at dockerhost1 (192.168.1.31) and timed out for
# every client in the house: dockerhost1 has a single NIC on vmbr1, behind
# OPNsense, and the home LAN is on OPNsense's WAN side, so nothing on
# 10.69.69.0/24 can route to that network. `service` is the only VM with an
# interface on both, and it terminates TLS for this name and proxies
# through -- see roles/applications/livecam/lan_proxy.yml in the ansible
# repo, which must stay in step with the address here.
#
# The OPNsense Unbound host override deliberately does NOT match this: it
# keeps answering 192.168.1.31, so hosts already inside the internal
# network go straight to dockerhost1 instead of hairpinning out to
# service's WAN leg and back. Rebind protection is why that override has to
# exist at all -- it discards private addresses returned from public DNS.
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
  records  = ["10.69.69.133"]
}
