package cdk_preflight

import rego.v1

_pf_vpnpsk_url := "https://docs.aws.amazon.com/vpn/latest/s2svpn/VPNTunnels.html"

_pf_vpnpsk_fix := "Use 8-64 characters of A-Z a-z 0-9 . _ and do not start with 0"

_pf_vpnpsk_bad(s) if count(s) < 8

_pf_vpnpsk_bad(s) if count(s) > 64

_pf_vpnpsk_bad(s) if not regex.match(`^[A-Za-z0-9._]+$`, s)

_pf_vpnpsk_bad(s) if startswith(s, "0")

violation contains make_diag_full("pf-ec2-vpn-pre-shared-key", "ERROR", name,
	sprintf("Properties.VpnTunnelOptionsSpecifications.%d.PreSharedKey", [item.index]),
	sprintf("PreSharedKey '%s' is not accepted: it must be 8-64 characters of [A-Za-z0-9._] and must not start with 0", [psk]),
	_pf_vpnpsk_fix, _pf_vpnpsk_url) if {
	some name in resources_of_type("AWS::EC2::VPNConnection")
	some item in flatten_list(name, "Properties.VpnTunnelOptionsSpecifications")
	psk := object.get(item.value, "PreSharedKey", null)
	is_string(psk)
	_pf_vpnpsk_bad(psk)
}
