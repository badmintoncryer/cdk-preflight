package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ec2-vpn-rekey-margin", "ERROR", name,
	sprintf("Properties.VpnTunnelOptionsSpecifications.%d.RekeyMarginTimeSeconds", [item.index]),
	sprintf("RekeyMarginTimeSeconds (%v) must be less than half of Phase2LifetimeSeconds (%v)", [m, p2]),
	"Lower RekeyMarginTimeSeconds below half of Phase2LifetimeSeconds",
	"https://docs.aws.amazon.com/vpn/latest/s2svpn/VPNTunnels.html") if {
	some name in resources_of_type("AWS::EC2::VPNConnection")
	some item in flatten_list(name, "Properties.VpnTunnelOptionsSpecifications")
	m := to_number(object.get(item.value, "RekeyMarginTimeSeconds", null))
	p2 := to_number(object.get(item.value, "Phase2LifetimeSeconds", null))
	m * 2 > p2
}
