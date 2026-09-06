package cdk_preflight

import rego.v1

_pf_vpntic_url := "https://docs.aws.amazon.com/vpn/latest/s2svpn/VPNTunnels.html"

_pf_vpntic_fix := "Use an unused /30 inside 169.254.0.0/16, for example 169.254.100.0/30"

_pf_vpntic_reserved := {
	"169.254.0.0/30", "169.254.1.0/30", "169.254.2.0/30", "169.254.3.0/30",
	"169.254.4.0/30", "169.254.5.0/30", "169.254.169.252/30",
}

_pf_vpntic_outside(c) if not startswith(c, "169.254.")

_pf_vpntic_outside(c) if to_number(split(c, "/")[1]) != 30

_pf_vpntic_cidr(item) := c if {
	c := object.get(item.value, "TunnelInsideCidr", null)
	is_string(c)
	regex.match(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$`, c)
}

violation contains make_diag_full("pf-ec2-vpn-tunnel-inside-cidr", "ERROR", name,
	sprintf("Properties.VpnTunnelOptionsSpecifications.%d.TunnelInsideCidr", [item.index]),
	sprintf("TunnelInsideCidr '%s' must be a /30 inside 169.254.0.0/16", [c]),
	_pf_vpntic_fix, _pf_vpntic_url) if {
	some name in resources_of_type("AWS::EC2::VPNConnection")
	some item in flatten_list(name, "Properties.VpnTunnelOptionsSpecifications")
	c := _pf_vpntic_cidr(item)
	_pf_vpntic_outside(c)
}

violation contains make_diag_full("pf-ec2-vpn-tunnel-inside-cidr", "ERROR", name,
	sprintf("Properties.VpnTunnelOptionsSpecifications.%d.TunnelInsideCidr", [item.index]),
	sprintf("TunnelInsideCidr '%s' is reserved by AWS and cannot be used for a tunnel", [c]),
	_pf_vpntic_fix, _pf_vpntic_url) if {
	some name in resources_of_type("AWS::EC2::VPNConnection")
	some item in flatten_list(name, "Properties.VpnTunnelOptionsSpecifications")
	c := _pf_vpntic_cidr(item)
	c in _pf_vpntic_reserved
}
